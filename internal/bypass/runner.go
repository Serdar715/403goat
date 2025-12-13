package bypass

import (
	"bufio"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
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

	// 2. Generate payloads
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	path := strings.TrimLeft(u.Path, "/")
	payloads := generatePayloadsByMode(cfg, path)

	return &Runner{
		Client:        client,
		Config:        cfg,
		Results:       make(chan utils.Result),
		Payloads:      payloads,
		BaseHeaders:   baseHeaders,
		DefaultMethod: method,
	}, nil
}

func (r *Runner) Run() {
	var wg sync.WaitGroup
	sem := make(chan struct{}, r.Config.Threads)

	// Calculate total requests approximately for progress bar
	// 1. Path Fuzzing (Prefixes + Suffixes)
	countPath := len(r.Payloads)
	// 2. Method Fuzzing (HTTP Methods)
	countMethods := len(utils.HTTPMethods)
	// 3. Header Fuzzing (Headers * IPs + Headers * 1)
	countHeaders := len(utils.BypassHeaders) * (len(utils.BypassIPs) + 1)
	// 4. Common Headers
	countCommon := 3

	totalRequests := countPath + countMethods + countHeaders + countCommon

	// Display scan info
	utils.LogInfo("Scan Configuration:")
	utils.LogInfo("  ├─ Path Payloads: %d", countPath)
	utils.LogInfo("  ├─ HTTP Methods: %d", countMethods)
	utils.LogInfo("  ├─ Header Tests: %d", countHeaders)
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

	// TASK 1: Path Fuzzing (Original Method + Fuzzed Path)
	for _, payload := range r.Payloads {
		r.submitTask(&wg, sem, bar, defaultMethod, payload, nil, "path")
	}

	// TASK 2: Method Fuzzing (Fuzzed Method + Original Path)
	u, _ := url.Parse(r.Config.URL)
	cleanPath := u.Path
	if cleanPath == "" {
		cleanPath = "/"
	}

	for _, method := range utils.HTTPMethods {
		if method == defaultMethod {
			continue
		}
		r.submitTask(&wg, sem, bar, method, cleanPath, nil, "method")
	}

	// TASK 3: Header Fuzzing (Original Method + Original Path + Fuzzed Headers)
	for _, h := range utils.BypassHeaders {
		r.submitTask(&wg, sem, bar, defaultMethod, cleanPath, map[string]string{h: "/"}, "header:"+h)

		for _, ip := range utils.BypassIPs {
			r.submitTask(&wg, sem, bar, defaultMethod, cleanPath, map[string]string{h: ip}, "header:"+h+"="+ip)
		}
	}

	// TASK 4: Common Bypass Headers
	r.submitTask(&wg, sem, bar, defaultMethod, cleanPath, map[string]string{"Referer": r.Config.URL}, "header:Referer")
	r.submitTask(&wg, sem, bar, defaultMethod, cleanPath, map[string]string{"Origin": r.Config.URL}, "header:Origin")
	r.submitTask(&wg, sem, bar, defaultMethod, cleanPath, map[string]string{"User-Agent": "Googlebot/2.1"}, "header:User-Agent")

	wg.Wait()
	close(r.Results)
}

func (r *Runner) submitTask(wg *sync.WaitGroup, sem chan struct{}, bar *pb.ProgressBar, method, payload string, extraHeaders map[string]string, technique string) {
	sem <- struct{}{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { <-sem }()

		// Rate limiting
		if r.Config.RateLimit > 0 {
			time.Sleep(time.Second / time.Duration(r.Config.RateLimit))
		}

		if bar != nil {
			bar.Increment()
		}
		r.executeRequest(method, payload, extraHeaders, technique)
	}()
}

func (r *Runner) executeRequest(method, payload string, extraHeaders map[string]string, technique string) {
	// If payload is already a full URL, use it
	if strings.HasPrefix(payload, "http") {
		r.doRequest(method, payload, payload, extraHeaders, technique)
		return
	}

	u, err := url.Parse(r.Config.URL)
	if err != nil {
		return
	}
	hostPart := fmt.Sprintf("%s://%s", u.Scheme, u.Host)

	var fullURL string
	if strings.HasPrefix(payload, "/") {
		fullURL = hostPart + payload
	} else {
		fullURL = hostPart + "/" + payload
	}

	r.doRequest(method, fullURL, payload, extraHeaders, technique)
}

func (r *Runner) doRequest(method, fullURL, payload string, extraHeaders map[string]string, technique string) {
	req, err := http.NewRequest(method, fullURL, nil)

	if err != nil {
		return
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
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			resCopy.RedirectURL = location

			// Make a request to the redirect location
			redirectReq, err := http.NewRequest("GET", location, nil)
			if err == nil {
				// Copy some headers
				redirectReq.Header.Set("User-Agent", req.Header.Get("User-Agent"))

				redirectResp, err := r.Client.Do(redirectReq)
				if err == nil {
					resCopy.RedirectStatus = redirectResp.StatusCode
					redirectResp.Body.Close()
				}
			}
		}
	}

	if r.Config.Verbose >= 2 {
		resCopy.Response = string(bodyBytes)
	}

	r.Results <- resCopy

	if r.Config.Delay > 0 {
		time.Sleep(time.Duration(r.Config.Delay) * time.Millisecond)
	}
}

func generatePayloadsByMode(cfg utils.Config, path string) []string {
	var payloads []string

	prefixes := utils.TopPrefixes
	suffixes := utils.TopSuffixes

	if cfg.PrefixFile != "" {
		prefixes = loadFromFile(cfg.PrefixFile)
	}
	if cfg.SuffixFile != "" {
		suffixes = loadFromFile(cfg.SuffixFile)
	}

	// 1. Original
	payloads = append(payloads, path)
	if !strings.HasPrefix(path, "/") {
		payloads = append(payloads, "/"+path)
	}

	// 2. Prefixes
	for _, p := range prefixes {
		// p usually ends with / or is something like /.;/
		// path is "admin"
		// result: /.;/admin

		// Clean up slashes for composition

		// But wait, some prefixes are "//" which become empty if we trim right.
		// Code from user: strings.TrimRight(p, "/") + "/" + strings.TrimLeft(path, "/")
		// If p is "//", trimright is "", so "/admin". This loses the double slash.
		// The user code's logic:
		// payloads = append(payloads, strings.TrimRight(p, "/")+"/"+strings.TrimLeft(path, "/"))

		// Let's interpret prefixes literally if they are special.
		// If p is "///", we want "///admin".
		// We'll trust simple concatenation mostly, but let's stick to user's logic if requested to "improve" it.
		// User's logic: strings.TrimRight(p, "/") + "/" + ...

		constructed := strings.TrimRight(p, "/") + "/" + strings.TrimLeft(path, "/")
		payloads = append(payloads, constructed)
	}

	// 3. Suffixes
	for _, s := range suffixes {
		// User code: strings.TrimLeft(path, "/") + s
		// If path is "admin", s is ".php", result "admin.php".
		// We should probably preserve leading slash if passing to full URL constructor

		constructed := strings.TrimLeft(path, "/") + s
		payloads = append(payloads, constructed)
	}

	// 4. Double (Prefix + Suffix)
	if cfg.DoublePayloads {
		for _, p := range prefixes {
			for _, s := range suffixes {
				constructed := strings.TrimRight(p, "/") + "/" + strings.TrimLeft(path, "/") + s
				payloads = append(payloads, constructed)
			}
		}
	}

	// 5. Random params
	if cfg.RandomParam {
		var randPayloads []string
		for _, p := range payloads {
			randPayloads = append(randPayloads, p+"?rand="+fmt.Sprintf("%d", rand.Intn(999999)))
		}
		payloads = append(payloads, randPayloads...)
	}

	// 6. Unicode bypass payloads
	if cfg.EnableUnicode {
		for _, u := range utils.UnicodePrefixes {
			constructed := strings.TrimRight(u, "/") + "/" + strings.TrimLeft(path, "/")
			payloads = append(payloads, constructed)
		}
	}

	// 7. Case manipulation
	if cfg.EnableCase {
		caseVariations := utils.GenerateCaseVariations(path)
		for _, cv := range caseVariations {
			if cv != path {
				payloads = append(payloads, cv)
				payloads = append(payloads, "/"+cv)
			}
		}
	}

	// 8. Double URL encoding
	if cfg.EnableDouble {
		for _, d := range utils.DoubleEncodedPrefixes {
			constructed := strings.TrimRight(d, "/") + "/" + strings.TrimLeft(path, "/")
			payloads = append(payloads, constructed)
		}
	}

	// 9. Custom wordlist
	if cfg.WordlistFile != "" {
		customWords := loadFromFile(cfg.WordlistFile)
		for _, word := range customWords {
			payloads = append(payloads, word)
			if !strings.HasPrefix(word, "/") {
				payloads = append(payloads, "/"+word)
			}
		}
	}

	payloads = deduplicatePayloads(payloads)

	if cfg.LimitPayloads > 0 && len(payloads) > cfg.LimitPayloads {
		payloads = payloads[:cfg.LimitPayloads]
	}

	return payloads
}

func loadFromFile(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return []string{}
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

func deduplicatePayloads(payloads []string) []string {
	seen := make(map[string]bool)
	var unique []string
	for _, p := range payloads {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	return unique
}
