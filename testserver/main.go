package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ADVANCED Test Server for 403goat
// Contains HARD security controls that are difficult to bypass

const (
	RED    = "\033[31m"
	GREEN  = "\033[32m"
	YELLOW = "\033[33m"
	BLUE   = "\033[34m"
	CYAN   = "\033[36m"
	RESET  = "\033[0m"
)

// Rate limiter
var (
	requestCounts = make(map[string]int)
	requestMutex  sync.Mutex
	secretKey     = "403goat-secret-key-2024"
)

func main() {
	printBanner()

	// Public endpoints
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/robots.txt", robotsHandler)

	// === MEDIUM-HARD LEVEL ===

	// 1. Strict IP validation (requires EXACT format: X.X.X.X)
	http.HandleFunc("/api/v1/internal", hardInternalHandler)

	// 2. Multiple header combination required
	http.HandleFunc("/admin/panel", hardAdminPanelHandler)

	// 3. Content-Type + Accept header validation
	http.HandleFunc("/api/v2/data", hardAPIDataHandler)

	// 4. Strict path normalization check
	http.HandleFunc("/secure/config", hardSecureConfigHandler)

	// 5. Rate limiting + IP check
	http.HandleFunc("/api/v1/users", hardUsersHandler)

	// === EXPERT LEVEL ===

	// 6. HMAC signature validation (weak key)
	http.HandleFunc("/api/v3/admin", expertHMACHandler)

	// 7. Base64 encoded path check
	http.HandleFunc("/encoded/", expertEncodedHandler)

	// 8. Multiple condition chain (4+ conditions)
	http.HandleFunc("/vault/secrets", expertVaultHandler)

	// 9. HTTP/2 specific check + header order
	http.HandleFunc("/http2/admin", expertHTTP2Handler)

	// 10. Unicode normalization bypass
	http.HandleFunc("/unicode/admin", expertUnicodeHandler)

	// === IMPOSSIBLE LEVEL (theoretically) ===

	// 11. Time-based token (rotates every 30 seconds)
	http.HandleFunc("/timed/access", impossibleTimedHandler)

	// 12. Chain of trust (3 endpoints must be hit in order)
	http.HandleFunc("/chain/step1", chainStep1Handler)
	http.HandleFunc("/chain/step2", chainStep2Handler)
	http.HandleFunc("/chain/step3", chainStep3Handler)

	// 13. Final Boss - requires everything
	http.HandleFunc("/ultimate/flag", ultimateFlagHandler)

	log.Println(CYAN + "[*] Starting ADVANCED test server on http://localhost:8888" + RESET)
	log.Println(RED + "[!] This server has HARD security controls" + RESET)
	log.Println("")
	log.Println(YELLOW + "=== DIFFICULTY LEVELS ===" + RESET)
	log.Println("  " + GREEN + "MEDIUM-HARD:" + RESET)
	log.Println("    /api/v1/internal  - Strict IP format validation")
	log.Println("    /admin/panel      - Multiple header combination")
	log.Println("    /api/v2/data      - Content-Type + Accept validation")
	log.Println("    /secure/config    - Strict path normalization")
	log.Println("    /api/v1/users     - Rate limiting + IP check")
	log.Println("")
	log.Println("  " + YELLOW + "EXPERT:" + RESET)
	log.Println("    /api/v3/admin     - HMAC signature required")
	log.Println("    /encoded/*        - Base64 encoded path")
	log.Println("    /vault/secrets    - 4+ conditions chain")
	log.Println("    /http2/admin      - HTTP/2 + header order")
	log.Println("    /unicode/admin    - Unicode normalization")
	log.Println("")
	log.Println("  " + RED + "IMPOSSIBLE:" + RESET)
	log.Println("    /timed/access     - Time-based rotating token")
	log.Println("    /chain/step1-3    - Chain of trust")
	log.Println("    /ultimate/flag    - 🏆 Final Boss")
	log.Println("")

	if err := http.ListenAndServe(":8888", nil); err != nil {
		log.Fatal(err)
	}
}

func printBanner() {
	fmt.Println(RED + `
    _   ___  ___ ___   _____ _____ ___ _____ 
   | | | \ \/ / / _ \ |_   _| ____/ __|_   _|
   | |_| |>  < | | | |  | | |  _| \__ \ | |  
   |  _  / /\ \| |_| |  | | | |___  __) || |  
   |_| |_/_/  \_\\___/   |_| |_____|____/ |_|  
                                               
   ╔═══════════════════════════════════════════╗
   ║   ADVANCED SECURITY TEST SERVER v2.0      ║
   ║   Difficulty: HARD / EXPERT / IMPOSSIBLE  ║
   ╚═══════════════════════════════════════════╝
` + RESET)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Advanced 403 Test Server</title></head>
<body style="font-family: 'Courier New'; background: #0a0a0a; color: #00ff00; padding: 40px;">
	<h1 style="color: #ff0000;">🔐 ADVANCED 403 Bypass Challenge</h1>
	<p>This server has <b>HARD security controls</b>. Good luck bypassing them!</p>
	<hr style="border-color: #333;">
	<h2 style="color: #ffff00;">Protected Endpoints:</h2>
	<pre style="background: #111; padding: 20px; border-left: 4px solid #ff0000;">
MEDIUM-HARD:
  /api/v1/internal  → Strict IP format validation
  /admin/panel      → Multiple header combination  
  /api/v2/data      → Content-Type + Accept validation
  /secure/config    → Strict path normalization check
  /api/v1/users     → Rate limiting + IP whitelist

EXPERT:
  /api/v3/admin     → HMAC signature required
  /encoded/*        → Base64 encoded path check
  /vault/secrets    → 4+ condition chain
  /http2/admin      → HTTP version check
  /unicode/admin    → Unicode normalization

IMPOSSIBLE:
  /timed/access     → Time-based rotating token
  /chain/step1-3    → Sequential chain of trust
  /ultimate/flag    → 🏆 FINAL BOSS
	</pre>
</body>
</html>
`)
}

func robotsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "User-agent: *\nDisallow: /api/\nDisallow: /admin/\nDisallow: /secure/\nDisallow: /vault/\nDisallow: /encoded/\nDisallow: /http2/\nDisallow: /unicode/\nDisallow: /timed/\nDisallow: /chain/\nDisallow: /ultimate/\n")
}

// ==================== MEDIUM-HARD LEVEL ====================

func hardInternalHandler(w http.ResponseWriter, r *http.Request) {
	// Strict IP format validation - must be EXACT format
	// Bypass: Need exact format like "127.0.0.1" not "127.1" or "localhost"
	xff := r.Header.Get("X-Forwarded-For")
	xrip := r.Header.Get("X-Real-IP")
	clientIP := r.Header.Get("Client-IP")

	// Strict IP regex
	ipRegex := regexp.MustCompile(`^(127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})$`)

	ips := []string{xff, xrip, clientIP}
	for _, ip := range ips {
		// Split by comma for X-Forwarded-For
		for _, singleIP := range strings.Split(ip, ",") {
			singleIP = strings.TrimSpace(singleIP)
			if ipRegex.MatchString(singleIP) {
				success(w, fmt.Sprintf("🎉 BYPASSED! Internal API Access!\n\nMatched IP: %s\nBypass: Strict IP format validation\nDifficulty: MEDIUM-HARD", singleIP))
				log.Printf(GREEN+"[BYPASS] /api/v1/internal - IP: %s"+RESET, singleIP)
				return
			}
		}
	}

	forbidden(w, "Access denied - Invalid internal IP format")
	log.Printf(RED+"[BLOCKED] /api/v1/internal - IPs: XFF=%s, XRI=%s, CIP=%s"+RESET, xff, xrip, clientIP)
}

func hardAdminPanelHandler(w http.ResponseWriter, r *http.Request) {
	// Requires MULTIPLE headers to be set correctly
	// Bypass: Need at least 3 specific headers
	conditions := 0
	var matched []string

	// Condition 1: X-Forwarded-For with internal IP
	if xff := r.Header.Get("X-Forwarded-For"); strings.Contains(xff, "127.0.0.1") || strings.Contains(xff, "10.") {
		conditions++
		matched = append(matched, "X-Forwarded-For")
	}

	// Condition 2: X-Requested-With: XMLHttpRequest
	if xrw := r.Header.Get("X-Requested-With"); strings.EqualFold(xrw, "XMLHttpRequest") {
		conditions++
		matched = append(matched, "X-Requested-With")
	}

	// Condition 3: Origin header from localhost
	if origin := r.Header.Get("Origin"); strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") {
		conditions++
		matched = append(matched, "Origin")
	}

	// Condition 4: Referer from admin
	if referer := r.Header.Get("Referer"); strings.Contains(strings.ToLower(referer), "admin") {
		conditions++
		matched = append(matched, "Referer")
	}

	// Need at least 3 conditions
	if conditions >= 3 {
		success(w, fmt.Sprintf("🎉 BYPASSED! Admin Panel Access!\n\nConditions met: %d/4\nHeaders: %s\nDifficulty: MEDIUM-HARD", conditions, strings.Join(matched, ", ")))
		log.Printf(GREEN+"[BYPASS] /admin/panel - Conditions: %d, Headers: %s"+RESET, conditions, strings.Join(matched, ", "))
		return
	}

	forbidden(w, fmt.Sprintf("Access denied - Need 3+ conditions (current: %d)", conditions))
	log.Printf(RED+"[BLOCKED] /admin/panel - Conditions: %d/4"+RESET, conditions)
}

func hardAPIDataHandler(w http.ResponseWriter, r *http.Request) {
	// Content-Type + Accept header validation
	// Bypass: Need specific Content-Type AND Accept combination

	contentType := r.Header.Get("Content-Type")
	accept := r.Header.Get("Accept")

	validContentTypes := []string{"application/json", "application/xml", "text/xml"}
	validAccepts := []string{"application/json", "*/*", "application/xml"}

	ctValid := false
	acValid := false

	for _, vct := range validContentTypes {
		if strings.Contains(contentType, vct) {
			ctValid = true
			break
		}
	}

	for _, vac := range validAccepts {
		if strings.Contains(accept, vac) {
			acValid = true
			break
		}
	}

	if ctValid && acValid {
		success(w, fmt.Sprintf("🎉 BYPASSED! API Data Access!\n\nContent-Type: %s\nAccept: %s\nDifficulty: MEDIUM-HARD", contentType, accept))
		log.Printf(GREEN+"[BYPASS] /api/v2/data - CT: %s, Accept: %s"+RESET, contentType, accept)
		return
	}

	forbidden(w, fmt.Sprintf("Invalid Content-Type (%v) or Accept (%v)", ctValid, acValid))
	log.Printf(RED+"[BLOCKED] /api/v2/data - CT: %s (%v), Accept: %s (%v)"+RESET, contentType, ctValid, accept, acValid)
}

func hardSecureConfigHandler(w http.ResponseWriter, r *http.Request) {
	// Strict path normalization - checks for encoding attempts
	// Bypass: Need to use specific encoding that passes validation

	rawPath := r.URL.RawPath
	if rawPath == "" {
		rawPath = r.URL.Path
	}

	// Check for bypass patterns
	bypassPatterns := []string{
		"%2e", "%2f", "%252e", "%252f", // URL encoding
		"..;", ";/", "/;", // Semicolon tricks
		"%00", "%0a", "%0d", // Null/newline
		"./", "../", "/..", // Path traversal
	}

	for _, pattern := range bypassPatterns {
		if strings.Contains(strings.ToLower(rawPath), pattern) {
			success(w, fmt.Sprintf("🎉 BYPASSED! Secure Config Access!\n\nPattern found: %s\nRaw path: %s\nDifficulty: MEDIUM-HARD", pattern, rawPath))
			log.Printf(GREEN+"[BYPASS] /secure/config - Pattern: %s, Path: %s"+RESET, pattern, rawPath)
			return
		}
	}

	forbidden(w, "Access denied - No bypass pattern detected")
	log.Printf(RED+"[BLOCKED] /secure/config - Path: %s, Raw: %s"+RESET, r.URL.Path, rawPath)
}

func hardUsersHandler(w http.ResponseWriter, r *http.Request) {
	// Rate limiting + IP validation
	clientAddr := r.RemoteAddr
	xff := r.Header.Get("X-Forwarded-For")

	// Rate limit check
	requestMutex.Lock()
	requestCounts[clientAddr]++
	count := requestCounts[clientAddr]
	requestMutex.Unlock()

	// Reset every 60 seconds (in real app would use proper rate limiter)
	go func() {
		time.Sleep(60 * time.Second)
		requestMutex.Lock()
		delete(requestCounts, clientAddr)
		requestMutex.Unlock()
	}()

	// Block if too many requests
	if count > 10 {
		w.WriteHeader(429)
		fmt.Fprintf(w, "Rate limited - too many requests")
		log.Printf(YELLOW+"[RATE LIMITED] /api/v1/users - Client: %s, Count: %d"+RESET, clientAddr, count)
		return
	}

	// Check for internal IP
	internalIPRegex := regexp.MustCompile(`^(127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)`)
	if internalIPRegex.MatchString(xff) {
		success(w, fmt.Sprintf("🎉 BYPASSED! Users API Access!\n\nX-Forwarded-For: %s\nRequest count: %d\nDifficulty: MEDIUM-HARD", xff, count))
		log.Printf(GREEN+"[BYPASS] /api/v1/users - XFF: %s"+RESET, xff)
		return
	}

	forbidden(w, "Access denied - Need internal IP")
	log.Printf(RED+"[BLOCKED] /api/v1/users - XFF: %s"+RESET, xff)
}

// ==================== EXPERT LEVEL ====================

func expertHMACHandler(w http.ResponseWriter, r *http.Request) {
	// HMAC signature validation with weak/guessable key
	// Bypass: X-Signature header with HMAC-SHA256 of path

	signature := r.Header.Get("X-Signature")
	authHeader := r.Header.Get("Authorization")

	// Check for weak signatures or known patterns
	if signature != "" {
		// Compute expected signature
		mac := hmac.New(sha256.New, []byte(secretKey))
		mac.Write([]byte(r.URL.Path))
		expectedSig := hex.EncodeToString(mac.Sum(nil))

		if signature == expectedSig[:16] || signature == "admin" || signature == "bypass" {
			success(w, fmt.Sprintf("🎉 BYPASSED! Admin API Access!\n\nSignature: %s\nExpected (first 16): %s\nDifficulty: EXPERT", signature, expectedSig[:16]))
			log.Printf(GREEN+"[BYPASS] /api/v3/admin - Signature: %s"+RESET, signature)
			return
		}
	}

	// Also check for Bearer token bypass
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "admin" || token == "internal" || strings.Contains(token, "eyJ") {
			success(w, fmt.Sprintf("🎉 BYPASSED! Admin API via Token!\n\nToken: %s\nDifficulty: EXPERT", token))
			log.Printf(GREEN+"[BYPASS] /api/v3/admin - Bearer token: %s"+RESET, token)
			return
		}
	}

	forbidden(w, "Invalid signature - HMAC-SHA256 required")
	log.Printf(RED+"[BLOCKED] /api/v3/admin - Sig: %s, Auth: %s"+RESET, signature, authHeader)
}

func expertEncodedHandler(w http.ResponseWriter, r *http.Request) {
	// Base64 encoded path check
	// Bypass: /encoded/YWRtaW4= (base64 of "admin")

	path := strings.TrimPrefix(r.URL.Path, "/encoded/")

	// Try to decode
	decoded, err := base64.StdEncoding.DecodeString(path)
	if err != nil {
		// Also try URL-safe base64
		decoded, err = base64.URLEncoding.DecodeString(path)
	}

	if err == nil {
		decodedStr := string(decoded)
		if strings.Contains(decodedStr, "admin") || strings.Contains(decodedStr, "secret") || strings.Contains(decodedStr, "flag") {
			success(w, fmt.Sprintf("🎉 BYPASSED! Encoded Path Access!\n\nEncoded: %s\nDecoded: %s\nDifficulty: EXPERT", path, decodedStr))
			log.Printf(GREEN+"[BYPASS] /encoded/ - Decoded: %s"+RESET, decodedStr)
			return
		}
	}

	forbidden(w, "Invalid encoded path - Need base64 of 'admin', 'secret', or 'flag'")
	log.Printf(RED+"[BLOCKED] /encoded/ - Path: %s"+RESET, path)
}

func expertVaultHandler(w http.ResponseWriter, r *http.Request) {
	// 4+ condition chain - ALL must be met
	conditions := 0
	var matched []string

	// Condition 1: Internal IP
	if xff := r.Header.Get("X-Forwarded-For"); strings.Contains(xff, "127.0.0.1") {
		conditions++
		matched = append(matched, "X-Forwarded-For=127.0.0.1")
	}

	// Condition 2: Bot User-Agent
	ua := r.Header.Get("User-Agent")
	if strings.Contains(ua, "Googlebot") || strings.Contains(ua, "internal") {
		conditions++
		matched = append(matched, "User-Agent=bot")
	}

	// Condition 3: JSON Accept
	if accept := r.Header.Get("Accept"); strings.Contains(accept, "application/json") {
		conditions++
		matched = append(matched, "Accept=json")
	}

	// Condition 4: POST or PUT method
	if r.Method == "POST" || r.Method == "PUT" {
		conditions++
		matched = append(matched, "Method="+r.Method)
	}

	// Condition 5: X-Requested-With
	if xrw := r.Header.Get("X-Requested-With"); xrw == "XMLHttpRequest" {
		conditions++
		matched = append(matched, "XMLHttpRequest")
	}

	// Need ALL 5 conditions
	if conditions >= 4 {
		success(w, fmt.Sprintf("🎉 BYPASSED! Vault Secrets Access!\n\nConditions: %d/5\nMatched: %s\n\nSecret: VAULT_KEY_2024_EXPERT_BYPASS\nDifficulty: EXPERT", conditions, strings.Join(matched, ", ")))
		log.Printf(GREEN+"[BYPASS] /vault/secrets - Conditions: %d/5"+RESET, conditions)
		return
	}

	forbidden(w, fmt.Sprintf("Need 4+ conditions (current: %d/5)", conditions))
	log.Printf(RED+"[BLOCKED] /vault/secrets - Conditions: %d/5"+RESET, conditions)
}

func expertHTTP2Handler(w http.ResponseWriter, r *http.Request) {
	// HTTP version + specific header combination
	// Bypass: HTTP/1.0 or specific protocol header

	proto := r.Proto
	xProto := r.Header.Get("X-Forwarded-Proto")
	upgrade := r.Header.Get("Upgrade")

	// Check for protocol manipulation
	if proto == "HTTP/1.0" || xProto == "http" || upgrade == "h2c" || upgrade == "websocket" {
		success(w, fmt.Sprintf("🎉 BYPASSED! HTTP2 Admin Access!\n\nProtocol: %s\nX-Forwarded-Proto: %s\nUpgrade: %s\nDifficulty: EXPERT", proto, xProto, upgrade))
		log.Printf(GREEN+"[BYPASS] /http2/admin - Proto: %s, XProto: %s, Upgrade: %s"+RESET, proto, xProto, upgrade)
		return
	}

	forbidden(w, fmt.Sprintf("Invalid protocol - Current: %s", proto))
	log.Printf(RED+"[BLOCKED] /http2/admin - Proto: %s"+RESET, proto)
}

func expertUnicodeHandler(w http.ResponseWriter, r *http.Request) {
	// Unicode normalization bypass
	// Bypass: Use unicode characters that normalize to "admin"

	path := r.URL.Path
	rawPath := r.URL.RawPath
	if rawPath == "" {
		rawPath = path
	}

	// Decode URL encoding
	decodedPath, _ := url.PathUnescape(rawPath)

	// Check for unicode variations
	unicodePatterns := []string{
		"%c0%af", "%c0%ae", "%e0%80%af", // Overlong encoding
		"%ef%bc",           // Fullwidth characters
		"\u0041", "\u0061", // Unicode letters
		"ⓐ", "ℂ", "ａ", "Ａ", // Special unicode
	}

	for _, pattern := range unicodePatterns {
		if strings.Contains(rawPath, pattern) || strings.Contains(decodedPath, pattern) {
			success(w, fmt.Sprintf("🎉 BYPASSED! Unicode Admin Access!\n\nPattern: %s\nPath: %s\nDecoded: %s\nDifficulty: EXPERT", pattern, rawPath, decodedPath))
			log.Printf(GREEN+"[BYPASS] /unicode/admin - Pattern: %s"+RESET, pattern)
			return
		}
	}

	// Also check for any non-ASCII characters
	for _, c := range rawPath {
		if c > 127 {
			success(w, fmt.Sprintf("🎉 BYPASSED! Unicode Admin Access!\n\nNon-ASCII char found: %c (%d)\nPath: %s\nDifficulty: EXPERT", c, c, rawPath))
			log.Printf(GREEN+"[BYPASS] /unicode/admin - Non-ASCII: %c"+RESET, c)
			return
		}
	}

	forbidden(w, "No unicode bypass pattern found")
	log.Printf(RED+"[BLOCKED] /unicode/admin - Path: %s"+RESET, rawPath)
}

// ==================== IMPOSSIBLE LEVEL ====================

func impossibleTimedHandler(w http.ResponseWriter, r *http.Request) {
	// Time-based rotating token
	// Bypass: Must provide token that matches current time window

	token := r.Header.Get("X-Time-Token")
	timestamp := time.Now().Unix()
	window := timestamp / 30 // 30 second windows

	// Expected token is hash of window
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(fmt.Sprintf("%d", window)))
	expectedToken := hex.EncodeToString(mac.Sum(nil))[:8]

	// Also accept some weak tokens for testing
	if token == expectedToken || token == "timed" || token == fmt.Sprintf("%d", window) {
		success(w, fmt.Sprintf("🎉 BYPASSED! Timed Access!\n\nToken: %s\nWindow: %d\nExpected: %s\nDifficulty: IMPOSSIBLE", token, window, expectedToken))
		log.Printf(GREEN+"[BYPASS] /timed/access - Token: %s, Window: %d"+RESET, token, window)
		return
	}

	forbidden(w, fmt.Sprintf("Invalid time token - Window: %d, Expected prefix: %s", window, expectedToken[:4]))
	log.Printf(RED+"[BLOCKED] /timed/access - Token: %s (expected: %s)"+RESET, token, expectedToken[:8])
}

var chainTokens = make(map[string]int)
var chainMutex sync.Mutex

func chainStep1Handler(w http.ResponseWriter, r *http.Request) {
	clientID := r.RemoteAddr + r.Header.Get("X-Forwarded-For")

	chainMutex.Lock()
	chainTokens[clientID] = 1
	chainMutex.Unlock()

	w.Header().Set("X-Chain-Token", "step1-complete")
	w.WriteHeader(200)
	fmt.Fprintf(w, "Step 1 complete. Proceed to /chain/step2 with X-Chain-Token header")
	log.Printf(BLUE+"[CHAIN] Step 1 complete for %s"+RESET, clientID)
}

func chainStep2Handler(w http.ResponseWriter, r *http.Request) {
	clientID := r.RemoteAddr + r.Header.Get("X-Forwarded-For")
	token := r.Header.Get("X-Chain-Token")

	chainMutex.Lock()
	step := chainTokens[clientID]
	chainMutex.Unlock()

	if step != 1 || token != "step1-complete" {
		forbidden(w, "Must complete step1 first")
		return
	}

	chainMutex.Lock()
	chainTokens[clientID] = 2
	chainMutex.Unlock()

	w.Header().Set("X-Chain-Token", "step2-complete")
	w.WriteHeader(200)
	fmt.Fprintf(w, "Step 2 complete. Proceed to /chain/step3 with X-Chain-Token: step2-complete")
	log.Printf(BLUE+"[CHAIN] Step 2 complete for %s"+RESET, clientID)
}

func chainStep3Handler(w http.ResponseWriter, r *http.Request) {
	clientID := r.RemoteAddr + r.Header.Get("X-Forwarded-For")
	token := r.Header.Get("X-Chain-Token")

	chainMutex.Lock()
	step := chainTokens[clientID]
	delete(chainTokens, clientID)
	chainMutex.Unlock()

	if step != 2 || token != "step2-complete" {
		forbidden(w, "Must complete step2 first")
		return
	}

	success(w, "🎉 CHAIN COMPLETE! All 3 steps passed!\n\nSecret: CHAIN_MASTER_FLAG_2024\nDifficulty: IMPOSSIBLE")
	log.Printf(GREEN+"[BYPASS] Chain complete for %s"+RESET, clientID)
}

func ultimateFlagHandler(w http.ResponseWriter, r *http.Request) {
	// ULTIMATE CHALLENGE - needs 6+ conditions
	conditions := 0
	var matched []string

	// 1. Internal IP
	if xff := r.Header.Get("X-Forwarded-For"); strings.Contains(xff, "127.0.0.1") {
		conditions++
		matched = append(matched, "IP")
	}

	// 2. Bot UA
	if ua := r.Header.Get("User-Agent"); strings.Contains(ua, "Googlebot") {
		conditions++
		matched = append(matched, "UA")
	}

	// 3. JSON
	if ct := r.Header.Get("Content-Type"); strings.Contains(ct, "json") {
		conditions++
		matched = append(matched, "CT")
	}

	// 4. Accept
	if acc := r.Header.Get("Accept"); strings.Contains(acc, "json") {
		conditions++
		matched = append(matched, "Accept")
	}

	// 5. Referer
	if ref := r.Header.Get("Referer"); strings.Contains(ref, "admin") {
		conditions++
		matched = append(matched, "Referer")
	}

	// 6. XMLHttpRequest
	if xrw := r.Header.Get("X-Requested-With"); xrw == "XMLHttpRequest" {
		conditions++
		matched = append(matched, "XHR")
	}

	// 7. Authorization
	if auth := r.Header.Get("Authorization"); auth != "" {
		conditions++
		matched = append(matched, "Auth")
	}

	// 8. POST method
	if r.Method == "POST" {
		conditions++
		matched = append(matched, "POST")
	}

	if conditions >= 6 {
		success(w, fmt.Sprintf(`
🏆🏆🏆 ULTIMATE FLAG CAPTURED! 🏆🏆🏆

===========================================
FLAG{403GOAT_ULTIMATE_BYPASS_MASTER_2024}
===========================================

Conditions met: %d/8
Matched: %s

You have conquered the IMPOSSIBLE challenge!
Difficulty: IMPOSSIBLE / ULTIMATE
`, conditions, strings.Join(matched, ", ")))
		log.Printf(GREEN+"[ULTIMATE] Flag captured! Conditions: %d/8"+RESET, conditions)
		return
	}

	forbidden(w, fmt.Sprintf("Ultimate challenge - Need 6+ conditions (current: %d/8)", conditions))
	log.Printf(RED+"[BLOCKED] /ultimate/flag - Conditions: %d/8"+RESET, conditions)
}

// ==================== HELPERS ====================

func forbidden(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(403)
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title></head>
<body style="font-family: monospace; background: #1a0000; color: #ff3333; padding: 40px; text-align: center;">
	<h1 style="font-size: 100px; margin: 0;">⛔ 403</h1>
	<h2>ACCESS DENIED</h2>
	<p style="color: #ff6666;">%s</p>
	<hr style="border-color: #330000;">
	<p style="color: #666;">Can you bypass this with 403goat?</p>
</body>
</html>
`, message)
}

func success(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>🎉 BYPASS SUCCESS!</title></head>
<body style="font-family: monospace; background: #001a00; color: #00ff00; padding: 40px;">
	<pre style="background: #002200; padding: 20px; border-radius: 8px; border: 2px solid #00ff00;">
%s
	</pre>
</body>
</html>
`, message)
}
