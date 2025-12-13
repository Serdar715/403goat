package utils

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type ParsedRequest struct {
	Method  string
	URL     *url.URL
	Headers http.Header
	Body    []byte
}

func ParseRawRequest(filename string, targetURL string) (*ParsedRequest, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open request file: %v", err)
	}

	// Normalize line endings (CRLF -> LF)
	content = bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n"))
	content = bytes.ReplaceAll(content, []byte("\r"), []byte("\n"))

	lines := strings.Split(string(content), "\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("empty request file")
	}

	// 1. Parse Request Line
	requestLine := strings.TrimSpace(lines[0])
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line: %s", requestLine)
	}
	method := parts[0]
	path := parts[1]

	// 2. Parse Headers
	headers := make(http.Header)
	var host string
	lineIndex := 1
	for lineIndex < len(lines) {
		line := strings.TrimSpace(lines[lineIndex])
		if line == "" {
			lineIndex++
			break
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx > 0 {
			key := strings.TrimSpace(line[:colonIdx])
			val := strings.TrimSpace(line[colonIdx+1:])
			headers.Set(key, val)

			if strings.ToLower(key) == "host" {
				host = val
			}
		}
		lineIndex++
	}

	// 3. Parse Body (remaining lines)
	var bodyLines []string
	for lineIndex < len(lines) {
		bodyLines = append(bodyLines, lines[lineIndex])
		lineIndex++
	}
	body := []byte(strings.Join(bodyLines, "\n"))

	// 4. Construct URL
	var finalURL *url.URL

	if targetURL != "" && targetURL != "https://" {
		// User provided -u, use that as base
		u, err := url.Parse(targetURL)
		if err != nil {
			return nil, fmt.Errorf("invalid target URL: %v", err)
		}
		finalURL = u
		if len(path) > 0 && !strings.HasPrefix(path, "http") {
			finalURL.Path = path
		}
	} else {
		// Build from Host header
		if host == "" {
			return nil, fmt.Errorf("no Host header found in request file. Headers found: %v", headers)
		}

		scheme := "https"
		if strings.Contains(host, ":80") && !strings.Contains(host, ":8080") {
			scheme = "http"
		}

		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		rawURL := fmt.Sprintf("%s://%s%s", scheme, host, path)
		finalURL, err = url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("failed to construct URL: %v", err)
		}
	}

	// Print parsed info (FFuf-like)
	LogInfo("Request File Parsed:")
	LogInfo("  ├─ Method: %s", method)
	LogInfo("  ├─ Path: %s", path)
	LogInfo("  ├─ Host: %s", host)
	LogInfo("  ├─ Headers: %d", len(headers))
	for k, v := range headers {
		LogInfo("  │   └─ %s: %s", k, strings.Join(v, ", "))
	}
	if len(body) > 0 {
		LogInfo("  └─ Body: %d bytes", len(body))
	}

	return &ParsedRequest{
		Method:  method,
		URL:     finalURL,
		Headers: headers,
		Body:    body,
	}, nil
}
