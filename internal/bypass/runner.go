package bypass

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Serdar715/403goat/internal/utils"

	"github.com/cheggaaa/pb/v3"
)

type Runner struct {
	Client        *http.Client
	Config        utils.Config
	Results       chan utils.Result
	Payloads      []string
	BaseHeaders   map[string]string
	DefaultMethod string
	BaselineLen   int64
	BaselineCode  int
	BaselineHash  string // MD5 hash of baseline response body
	RateLimitLock sync.Mutex
	ParsedURL     *url.URL
}

func NewRunner(cfg utils.Config, client *http.Client) (*Runner, error) {
	var baseHeaders map[string]string
	var targetURLStr string = cfg.URL
	var method string = "GET"

	// 1. If Request File is provided, parse it
	if cfg.RequestFile != "" {
		parsed, err := utils.ParseRawRequest(cfg.RequestFile, cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse request file: %v", err)
		}
		targetURLStr = parsed.URL.String()

		// Convert http.Header to map[string]string
		baseHeaders = make(map[string]string)
		for k, v := range parsed.Headers {
			baseHeaders[k] = strings.Join(v, ", ")
		}

		method = parsed.Method
		// Update cfg.URL so other parts use the correct full URL
		cfg.URL = targetURLStr
	}

	// Helper to parse URL once
	parsedURL, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	// 2. Generate payloads
	var basePaths []string

	// If wordlist is provided, use it as list of paths
	if cfg.WordlistFile != "" {
		words := LoadFromFile(cfg.WordlistFile)
		if len(words) > 0 {
			for _, w := range words {
				// Normalize path: ensure no leading slash for consistency unless crucial
				clean := strings.TrimLeft(w, "/")
				if clean != "" {
					basePaths = append(basePaths, clean)
				}
			}
		} else {
			utils.LogInfo("Wordlist file is empty or could not be read. Falling back to URL path.")
		}
	}

	// If no base paths yet (no wordlist or empty), use the URL's path
	if len(basePaths) == 0 {
		basePaths = append(basePaths, strings.TrimLeft(parsedURL.Path, "/"))
	}

	var payloads []string
	for _, p := range basePaths {
		// Generate bypass variations for THIS specific path
		vars := GeneratePayloadsByMode(cfg, p)
		payloads = append(payloads, vars...)
	}

	// Deduplicate massive list
	payloads = DeduplicatePayloads(payloads)

	return &Runner{
		Client:        client,
		Config:        cfg,
		Results:       make(chan utils.Result),
		Payloads:      payloads,
		BaseHeaders:   baseHeaders,
		DefaultMethod: method,
		ParsedURL:     parsedURL,
	}, nil
}

func (r *Runner) Run(ctx context.Context) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, r.Config.Threads)

	// Calculate total requests approximately for progress bar

	// Load extra headers and IPs
	extraHeaders, extraIPs := LoadExtraHeadersAndIPs(r.Config)
	allIPHeaders := append(utils.IPHeaders, extraHeaders...)
	allBypassIPs := append(utils.BypassIPs, extraIPs...)

	// Add custom bypass IP if specified (-i flag)
	if r.Config.CustomBypassIP != "" {
		allBypassIPs = append(allBypassIPs, r.Config.CustomBypassIP)
	}

	// Deduplicate just in case
	allIPHeaders = DeduplicatePayloads(allIPHeaders)
	allBypassIPs = DeduplicatePayloads(allBypassIPs)

	// 1. Path Fuzzing (Prefixes + Suffixes)
	countPath := len(r.Payloads)
	// 2. Method Fuzzing (HTTP Methods)
	countMethods := len(utils.HTTPMethods)
	// 3. Header Fuzzing - Refined Count
	countIPHeaders := len(allIPHeaders) * len(allBypassIPs)
	countURLHeaders := len(utils.URLHeaders) * 3 // /path, /path/, fullURL
	countHostHeaders := len(utils.HostHeaders) * len(utils.HostHeaderValues)
	countSchemeHeaders := len(utils.SchemeHeaders) * 2 // http, https

	// 4. Common Headers
	countCommon := 3
	// 5. Method Override Headers
	countMethodOverride := len(utils.MethodOverrideHeaders) * len(utils.MethodOverrideValues)
	// 6. Host Header Attacks
	countHostHeader := len(utils.HostHeaderValues)
	// 7. Content-Type Manipulation
	countContentType := len(utils.ContentTypeValues)
	// 8. Accept Header Manipulation
	countAcceptHeader := len(utils.AcceptHeaderValues)
	// 9. Cache Deception
	countCacheDeception := len(utils.CacheDeceptionSuffixes)
	// 10. Path Normalization
	countPathNorm := len(utils.PathNormalizationPayloads)

	// 11. Extensions
	countExtensions := len(utils.ExtensionPayloads)
	// 12. Parameter Pollution
	countParams := len(utils.ParameterPollutionPayloads)
	// 13. Smuggling
	countSmuggling := len(utils.SmugglingHeaders) * len(utils.SmugglingValues)
	// 14. Method Case Switching (only if enabled)
	countMethodCase := 0
	if r.Config.EnableMethodCase {
		countMethodCase = len(utils.HTTPMethodCases)
	}
	// 15. User-Agent Bypass
	countUserAgent := len(utils.UserAgentBypass)
	// 16. Referer Bypass
	countReferer := len(utils.RefererBypass)
	// 17. Combo Attacks (multi-header bypass)
	countCombo := len(utils.ComboAttacks)
	// 18. Auth Tokens
	countAuthTokens := len(utils.CommonAuthTokens)
	// 19. Signatures
	countSignatures := len(utils.CommonSignatures)
	// 20. X-Requested-With
	countXRW := len(utils.XRequestedWithValues)
	// 21. Path + Header Combo
	countPathCombo := 16 + 5 // 16 path variations + 5 POST variants

	totalRequests := countPath + countMethods + countIPHeaders + countURLHeaders + countHostHeaders + countSchemeHeaders + countCommon +
		countMethodOverride + countHostHeader + countContentType + countAcceptHeader + countCacheDeception + countPathNorm +
		countExtensions + countParams + countSmuggling + countMethodCase + countUserAgent + countReferer +
		countCombo + countAuthTokens + countSignatures + countXRW + countPathCombo

	// Display scan info
	utils.LogInfo("Scan Configuration:")
	if r.Config.AutoCalibration {
		r.Calibrate()
	}
	utils.LogInfo("  ├─ Path Payloads: %d", countPath)
	utils.LogInfo("  ├─ HTTP Methods: %d", countMethods)
	utils.LogInfo("  ├─ IP Header Tests: %d", countIPHeaders)
	utils.LogInfo("  ├─ URL Header Tests: %d", countURLHeaders)
	utils.LogInfo("  ├─ Host Header Tests: %d", countHostHeaders)
	utils.LogInfo("  ├─ Scheme Header Tests: %d", countSchemeHeaders)
	utils.LogInfo("  ├─ Method Override: %d", countMethodOverride)
	utils.LogInfo("  ├─ Host Header: %d", countHostHeader)
	utils.LogInfo("  ├─ Content-Type: %d", countContentType)
	utils.LogInfo("  ├─ Accept Header: %d", countAcceptHeader)
	utils.LogInfo("  ├─ Cache Deception: %d", countCacheDeception)
	utils.LogInfo("  ├─ Path Normalization: %d", countPathNorm)
	utils.LogInfo("  ├─ Extensions: %d", countExtensions)
	utils.LogInfo("  ├─ Param Pollution: %d", countParams)
	utils.LogInfo("  ├─ Smuggling: %d", countSmuggling)
	if countMethodCase > 0 {
		utils.LogInfo("  ├─ Method Case: %d", countMethodCase)
	}
	utils.LogInfo("  ├─ User-Agent Bypass: %d", countUserAgent)
	utils.LogInfo("  ├─ Referer Bypass: %d", countReferer)
	utils.LogInfo("  ├─ Combo Attacks: %d", countCombo)
	utils.LogInfo("  ├─ Auth Tokens: %d", countAuthTokens)
	utils.LogInfo("  ├─ Signatures: %d", countSignatures)
	utils.LogInfo("  ├─ X-Requested-With: %d", countXRW)
	utils.LogInfo("  ├─ Path+Header Combo: %d", countPathCombo)
	utils.LogInfo("  └─ Total Requests: %d", totalRequests)

	if len(r.Config.CustomHeaders) > 0 {
		utils.LogInfo("Custom Headers:")
		for _, h := range r.Config.CustomHeaders {
			utils.LogInfo("  └─ %s", h)
		}
	}

	var bar *pb.ProgressBar
	if r.Config.ShowProgress && r.Config.Verbose == 0 {
		bar = pb.StartNew(totalRequests)
		bar.SetTemplate(pb.Simple)
		defer bar.Finish()
	}

	// Use default method from request file or GET
	defaultMethod := r.DefaultMethod

	// Use parsed URL path for clean path
	cleanPath := r.ParsedURL.Path
	if cleanPath == "" {
		cleanPath = "/"
	}

	// TASK 1: Path Fuzzing (Original Method + Fuzzed Path)
	for _, payload := range r.Payloads {
		r.submitTask(ctx, &wg, sem, bar, defaultMethod, payload, nil, "path")
	}

	// TASK 2: Method Fuzzing (Fuzzed Method + Original Path)
	// cleanPath is already computed above
	for _, method := range utils.HTTPMethods {
		if method == defaultMethod {
			continue
		}
		r.submitTask(ctx, &wg, sem, bar, method, cleanPath, nil, "method")
	}

	// TASK 3: Header Fuzzing (Specific per Header Type)

	// 3a. IP Headers -> Use BypassIPs
	for _, h := range allIPHeaders {
		for _, ip := range allBypassIPs {
			r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, map[string]string{h: ip}, "header-ip:"+h+"="+ip)
		}
	}

	// 3b. URL Headers
	u := r.ParsedURL // Reuse parsed URL
	fullURLPayload := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, cleanPath)
	urlVariants := []string{cleanPath, strings.TrimRight(cleanPath, "/") + "/", fullURLPayload}

	for _, h := range utils.URLHeaders {
		for _, v := range urlVariants {
			r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, map[string]string{h: v}, "header-url:"+h)
		}
	}

	// 3c. Host Headers
	for _, h := range utils.HostHeaders {
		for _, hv := range utils.HostHeaderValues {
			r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, map[string]string{h: hv}, "header-host:"+h+"="+hv)
		}
	}

	// 3d. Scheme Headers
	schemes := []string{"http", "https"}
	for _, h := range utils.SchemeHeaders {
		for _, s := range schemes {
			r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, map[string]string{h: s}, "header-scheme:"+h+"="+s)
		}
	}

	// TASK 4: Common Bypass Headers
	r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, map[string]string{"Referer": r.Config.URL}, "header:Referer")
	r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, map[string]string{"Origin": r.Config.URL}, "header:Origin")
	r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, map[string]string{"User-Agent": "Googlebot/2.1"}, "header:User-Agent")

	// TASK 5: Method Override Headers
	for _, overrideHeader := range utils.MethodOverrideHeaders {
		for _, overrideMethod := range utils.MethodOverrideValues {
			r.submitTask(ctx, &wg, sem, bar, "POST", cleanPath, map[string]string{overrideHeader: overrideMethod}, "method-override:"+overrideHeader+"="+overrideMethod)
		}
	}

	// TASK 6: Host Header Attacks
	for _, hostValue := range utils.HostHeaderValues {
		r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, map[string]string{"Host": hostValue}, "host-header:"+hostValue)
	}

	// TASK 7: Content-Type
	for _, contentType := range utils.ContentTypeValues {
		r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, map[string]string{"Content-Type": contentType}, "content-type:"+contentType)
	}

	// TASK 8: Accept Header
	for _, acceptValue := range utils.AcceptHeaderValues {
		r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, map[string]string{"Accept": acceptValue}, "accept:"+acceptValue)
	}

	// TASK 9: Cache Deception
	for _, suffix := range utils.CacheDeceptionSuffixes {
		cachePayload := strings.TrimRight(cleanPath, "/") + suffix
		r.submitTask(ctx, &wg, sem, bar, defaultMethod, cachePayload, nil, "cache-deception:"+suffix)
	}

	// TASK 10: Path Normalization
	for _, normPayload := range utils.PathNormalizationPayloads {
		normPath := strings.TrimRight(cleanPath, "/") + normPayload
		r.submitTask(ctx, &wg, sem, bar, defaultMethod, normPath, nil, "path-norm:"+normPayload)
	}

	// TASK 11: Extensions
	for _, ext := range utils.ExtensionPayloads {
		extPayload := strings.TrimRight(cleanPath, "/") + ext
		r.submitTask(ctx, &wg, sem, bar, defaultMethod, extPayload, nil, "extension:"+ext)
	}

	// TASK 12: Parameter Pollution
	for _, param := range utils.ParameterPollutionPayloads {
		paramPayload := strings.TrimRight(cleanPath, "/") + param
		r.submitTask(ctx, &wg, sem, bar, defaultMethod, paramPayload, nil, "param-pollution:"+param)
	}

	// TASK 13: Smuggling
	for _, sHeader := range utils.SmugglingHeaders {
		for _, sValue := range utils.SmugglingValues {
			r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, map[string]string{sHeader: sValue}, "smuggling:"+sHeader+"="+sValue)
		}
	}

	// TASK 14: Method Case Switching
	if r.Config.EnableMethodCase {
		for _, methodCase := range utils.HTTPMethodCases {
			r.submitTask(ctx, &wg, sem, bar, methodCase, cleanPath, nil, "method-case:"+methodCase)
		}
	}

	// TASK 15: User-Agent Bypass
	for _, ua := range utils.UserAgentBypass {
		r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, map[string]string{"User-Agent": ua}, "user-agent:"+ua[:min(20, len(ua))])
	}

	// TASK 16: Referer Bypass
	for _, ref := range utils.RefererBypass {
		r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, map[string]string{"Referer": ref}, "referer:"+ref)
	}

	// TASK 18: Auth Token Bypass (Prioritize single vectors)
	for _, token := range utils.CommonAuthTokens {
		authHeader := token
		if !strings.HasPrefix(token, "Bearer ") && !strings.HasPrefix(token, "Basic ") && !strings.HasPrefix(token, "eyJ") {
			authHeader = "Bearer " + token
		}
		r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, map[string]string{"Authorization": authHeader}, "auth:"+token[:min(15, len(token))])
	}

	// TASK 19: Signature Bypass
	for _, sig := range utils.CommonSignatures {
		headers := map[string]string{
			"X-Signature":  sig,
			"X-Auth-Token": sig,
			"X-API-Key":    sig,
		}
		r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, headers, "signature:"+sig[:min(10, len(sig))])
	}

	// TASK 20: X-Requested-With
	for _, xrw := range utils.XRequestedWithValues {
		r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, map[string]string{"X-Requested-With": xrw}, "x-requested-with:"+xrw)
	}

	// --- END PHASE 1: SINGLE VECTORS ---
	// Wait for all single vector tasks to complete before starting heavy combos
	wg.Wait()

	if r.Config.Verbose >= 0 {
		// Use fmt to avoid logger prefix messing up UI flow, or just clear line
		if bar != nil {
			fmt.Print("\r") // Clear current line (progress bar)
		}
		utils.LogInfo("Single vectors completed. Starting advanced combo attacks...")
	}

	// TASK 17: Combo Attacks (multi-header)
	for _, combo := range utils.ComboAttacks {
		r.submitTask(ctx, &wg, sem, bar, defaultMethod, cleanPath, combo.Headers, "combo:"+combo.Name)
		if combo.Name == "method-override-post" || combo.Name == "full-bypass" {
			r.submitTask(ctx, &wg, sem, bar, "POST", cleanPath, combo.Headers, "combo-post:"+combo.Name)
		}
	}

	// TASK 21: Path + Header Combo
	pathVariations := []string{
		"/../" + strings.TrimPrefix(cleanPath, "/"),
		"/..;/" + strings.TrimPrefix(cleanPath, "/"),
		"/.;/" + strings.TrimPrefix(cleanPath, "/"),
		"/%2e/" + strings.TrimPrefix(cleanPath, "/"),
		"/%2e%2e/" + strings.TrimPrefix(cleanPath, "/"),
		"/./" + strings.TrimPrefix(cleanPath, "/"),
		"//" + strings.TrimPrefix(cleanPath, "/"),
		cleanPath + "/",
		cleanPath + "//",
		cleanPath + "/.",
		cleanPath + "/..",
		cleanPath + "%00",
		cleanPath + "%20",
		cleanPath + "?",
		cleanPath + "#",
		cleanPath + ";",
	}

	fullBypassHeaders := map[string]string{
		"X-Forwarded-For":  "127.0.0.1",
		"X-Real-IP":        "127.0.0.1",
		"X-Originating-IP": "127.0.0.1",
		"Client-IP":        "127.0.0.1",
		"X-Forwarded-Host": "localhost",
		"User-Agent":       "Googlebot/2.1",
		"Referer":          "http://localhost/admin",
		"Origin":           "http://localhost",
		"X-Requested-With": "XMLHttpRequest",
		"Accept":           "application/json",
	}

	for _, pathVar := range pathVariations {
		r.submitTask(ctx, &wg, sem, bar, defaultMethod, pathVar, fullBypassHeaders, "path-combo:"+pathVar)
	}

	// Also try path variations with POST method
	for _, pathVar := range pathVariations[:5] { // First 5 most effective
		r.submitTask(ctx, &wg, sem, bar, "POST", pathVar, fullBypassHeaders, "path-combo-post:"+pathVar)
	}

	wg.Wait()
	close(r.Results)
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (r *Runner) submitTask(ctx context.Context, wg *sync.WaitGroup, sem chan struct{}, bar *pb.ProgressBar, method, payload string, extraHeaders map[string]string, technique string) {
	select {
	case <-ctx.Done():
		return
	case sem <- struct{}{}:
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { <-sem }()

		// Rate limiting
		r.RateLimitLock.Lock()
		// delay is req/s setting
		rateLimit := r.Config.RateLimit
		// customDelay is ms setting
		fixedDelay := r.Config.Delay
		r.RateLimitLock.Unlock()

		if rateLimit > 0 {
			// Basic approximation: sleep duration = 1s / rate
			// Note: This is per-goroutine. For precise global rate limiting across all threads,
			// a token bucket limiter is needed. For now, we stick to the existing logic pattern
			// but optimize implementation.
			time.Sleep(time.Second / time.Duration(rateLimit))
		} else if fixedDelay > 0 {
			time.Sleep(time.Duration(fixedDelay) * time.Millisecond)
		}

		if ctx.Err() != nil {
			return
		}

		if ctx.Err() != nil {
			return
		}

		if bar != nil {
			bar.Increment()
		}
		r.executeRequest(ctx, method, payload, extraHeaders, technique)
	}()
}

func (r *Runner) executeRequest(ctx context.Context, method, payload string, extraHeaders map[string]string, technique string) {
	// If payload is already a full URL, use it
	if strings.HasPrefix(payload, "http") {
		r.doRequest(ctx, method, payload, payload, extraHeaders, technique)
		return
	}

	// Optimize: Use pre-parsed URL
	u := r.ParsedURL
	hostPart := fmt.Sprintf("%s://%s", u.Scheme, u.Host)

	var fullURL string
	if strings.HasPrefix(payload, "/") {
		fullURL = hostPart + payload
	} else {
		fullURL = hostPart + "/" + payload
	}

	r.doRequest(ctx, method, fullURL, payload, extraHeaders, technique)
}

func (r *Runner) doRequest(ctx context.Context, method, fullURL, payload string, extraHeaders map[string]string, technique string) {
	// If FollowRedirects is NOT set in config, simple client usage
	// If FollowRedirects IS set, we need to handle it.
	// Actually, standard Go client follows redirects by default. The current code *manually* checks 3xx and requests it again.
	// We will stick to the manual logic as it gives more control on logging.

	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)

	if err != nil {
		return
	}

	// Ensure Host header is correct if manually set (e.g. Host Header attack)
	// Go sets req.Host from URL by default, but we can override it.
	if val, ok := extraHeaders["Host"]; ok {
		req.Host = val
	}

	// FIX: Prevent Go from normalizing paths (e.g., /%2e/ -> /)
	// If the payload contains special characters that might be normalized, we force Opaque.
	if strings.Contains(payload, "%") || strings.Contains(payload, "..") {
		// If payload started with http, we have full URL. We need to extract the path part for Opaque if we want to be safe,
		// but Opaque usually works best when it replaces the RequestURI.
		// However, for http.Client with NewRequest, if Opaque is set, it is used as the RequestURI.

		// Case 1: Payload is path (starts with /)
		if strings.HasPrefix(payload, "/") {
			req.URL.Opaque = payload
		} else if strings.HasPrefix(payload, "http") {
			// Case 2: Payload is full URL (http://target.com/%2e/foo)
			// We need to extract the path+query from it.
			// Simple split finding the third /
			parts := strings.SplitN(payload, "/", 4)
			if len(parts) >= 4 {
				req.URL.Opaque = "/" + parts[3] // This might be brittle for some inputs
			}
		}
	}

	// Set Base Headers from File or Default
	if len(r.BaseHeaders) > 0 {
		for k, v := range r.BaseHeaders {
			req.Header.Set(k, v)
		}
	}

	// Apply Custom Headers from -H flag
	for _, h := range r.Config.CustomHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	// Random User Agent if not set in base
	if req.Header.Get("User-Agent") == "" {
		uaIndex := rand.Intn(len(utils.UserAgents))
		req.Header.Set("User-Agent", utils.UserAgents[uaIndex])
	}

	// Apply Extra Headers (Payloads)
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := r.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	duration := time.Since(start)

	// Read body for filtering
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyLen := int64(len(bodyBytes))

	// Filter by status codes
	for _, fc := range r.Config.FilterCodes {
		if resp.StatusCode == fc {
			return
		}
	}

	// Match codes filter (if set, only show these codes)
	if len(r.Config.MatchCodes) > 0 {
		matched := false
		for _, mc := range r.Config.MatchCodes {
			if resp.StatusCode == mc {
				matched = true
				break
			}
		}
		if !matched {
			return
		}
	}

	// Auto-Calibration Filter - Smart False Positive Detection
	if r.Config.AutoCalibration && r.BaselineLen > 0 {
		// Calculate content hash for this response
		responseHash := fmt.Sprintf("%x", md5.Sum(bodyBytes))

		// Check 1: Exact hash match (identical content = definite false positive)
		if responseHash == r.BaselineHash {
			return // Identical response to baseline, skip
		}

		// Check 2: Same status code + similar length = likely false positive
		diff := bodyLen - r.BaselineLen
		if diff < 0 {
			diff = -diff
		}

		tolerance := r.Config.AutoCalibrationTolerance
		if tolerance == 0 {
			tolerance = 10 // Default 10 bytes
		}

		isBaselineStatus := (resp.StatusCode == r.BaselineCode)
		isSimilarLen := (diff <= tolerance)

		// Filter only if BOTH status AND length are similar to baseline
		// This ensures we don't filter real bypasses (e.g., 200 vs 403 baseline)
		if isBaselineStatus && isSimilarLen {
			return // Likely false positive, skip
		}
	}

	// Filter by response size
	if r.Config.FilterSize > 0 && bodyLen == r.Config.FilterSize {
		return
	}

	// Match regex in response body
	if r.Config.MatchRegex != "" {
		matched, _ := regexp.MatchString(r.Config.MatchRegex, string(bodyBytes))
		if !matched {
			return
		}
	}

	resCopy := utils.Result{
		Method:     method,
		StatusCode: resp.StatusCode,
		ContentLen: bodyLen,
		Headers:    make(map[string]string),
		Payload:    payload,
		Technique:  technique,
		URL:        fullURL,
		Time:       duration,
	}

	for k, v := range resp.Header {
		resCopy.Headers[k] = strings.Join(v, ", ")
	}

	// Follow redirects for 3xx responses
	if !r.Config.NoRedirects && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			resCopy.RedirectURL = location

			// Resolve relative URL
			fullRedirectURL := location
			if strings.HasPrefix(location, "/") {
				u := r.ParsedURL
				fullRedirectURL = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, location)
			} else if !strings.HasPrefix(location, "http") {
				// Relative path without leading slash? simpler to assume relative to root for now
				// or join with current path. But Location header usually is absolute or absolute path.
				// Let's try to parse it properly
				if parsedLoc, err := url.Parse(location); err == nil {
					fullRedirectURL = r.ParsedURL.ResolveReference(parsedLoc).String()
				}
			}

			// Make a request to the redirect location
			redirectReq, err := http.NewRequestWithContext(ctx, "GET", fullRedirectURL, nil)
			if err == nil {
				// Copy some headers
				redirectReq.Header.Set("User-Agent", req.Header.Get("User-Agent"))

				// Add cookies if any (basic session support for redirect)
				for _, cookie := range resp.Cookies() {
					redirectReq.AddCookie(cookie)
				}

				redirectResp, err := r.Client.Do(redirectReq)
				if err == nil {
					redBodyBytes, _ := io.ReadAll(redirectResp.Body)
					resCopy.RedirectStatus = redirectResp.StatusCode
					redirectResp.Body.Close()

					// Smart Filter: Check if redirect lands on a "trap" or baseline page
					if r.Config.AutoCalibration {
						// 1. Check Content Hash
						redirectHash := fmt.Sprintf("%x", md5.Sum(redBodyBytes))
						if redirectHash == r.BaselineHash {
							return // Redirected to 404/Blocking page -> False Positive
						}

						// 2. Check Trap Keywords in URL
						trapKeywords := []string{"login", "signin", "auth", "error", "denied", "unauthorized", "404", "403"}
						lowerLoc := strings.ToLower(location)
						for _, kw := range trapKeywords {
							if strings.Contains(lowerLoc, kw) {
								return // Redirected to Login/Error -> False Positive
							}
						}
					}
				}
			}
		}
	}

	if r.Config.Verbose >= 2 {
		resCopy.Response = string(bodyBytes)
	}

	r.Results <- resCopy

	// Adaptive Rate Limiting: If 429, back off
	if resp.StatusCode == 429 {
		r.RateLimitLock.Lock()
		r.Config.Delay += 500 // Add 500ms to delay
		if r.Config.Delay > 5000 {
			r.Config.Delay = 5000 // Cap at 5s
		}
		currentDelay := r.Config.Delay
		r.RateLimitLock.Unlock()

		if r.Config.Verbose >= 1 {
			utils.LogInfo("Rate limit detected (429). Increasing delay to %d ms", currentDelay)
		}
		time.Sleep(2 * time.Second) // Immediate penalty sleep
	}
}

func (r *Runner) Calibrate() {
	// Generate random non-existent path for baseline
	randPath := fmt.Sprintf("/403goat_calibration_%d_%d", time.Now().Unix(), rand.Intn(10000))
	u, _ := url.Parse(r.Config.URL)
	target := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, randPath)

	req, _ := http.NewRequest("GET", target, nil)
	req.Header.Set("User-Agent", utils.UserAgents[0])

	resp, err := r.Client.Do(req)
	if err != nil {
		utils.LogError("Auto-Calibration failed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	r.BaselineLen = int64(len(body))
	r.BaselineCode = resp.StatusCode
	r.BaselineHash = fmt.Sprintf("%x", md5.Sum(body))

	// Set default tolerance if not specified
	if r.Config.AutoCalibrationTolerance == 0 {
		r.Config.AutoCalibrationTolerance = 10 // Default 10 bytes tolerance
	}

	utils.LogSuccess("Auto-Calibration (AC) Enabled:")
	utils.LogInfo("  ├─ Baseline Status: %d", r.BaselineCode)
	utils.LogInfo("  ├─ Baseline Length: %d bytes", r.BaselineLen)
	utils.LogInfo("  ├─ Baseline Hash: %s", r.BaselineHash[:16]+"...")
	utils.LogInfo("  ├─ Tolerance: ±%d bytes", r.Config.AutoCalibrationTolerance)
	utils.LogInfo("  └─ Calibration Path: %s", randPath)
}
