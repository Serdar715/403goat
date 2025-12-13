package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

type ParsedRequest struct {
	Method  string
	URL     *url.URL
	Headers map[string]string
	Body    []byte
}

func ParseRawRequest(filename string, targetURL string) (*ParsedRequest, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open request file: %v", err)
	}
	defer file.Close()

	// Read the entire file into a buffer to handle body parsing easily
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("could not read request file: %v", err)
	}

	reader := bufio.NewReader(bytes.NewReader(content))

	// 1. Parse Request Line
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("malformed request file: %v", err)
	}
	line = strings.TrimSpace(line)
	parts := strings.Split(line, " ")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line: %s", line)
	}
	method := parts[0]
	path := parts[1]

	// 2. Parse Headers
	headers := make(map[string]string)
	var host string
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}

		// Remove CR and LF and other whitespace
		cleanLine := strings.TrimSpace(line)
		cleanLine = strings.Trim(cleanLine, "\r\n")

		if cleanLine == "" {
			// End of headers
			break
		}

		// Split header into key: value
		colonIdx := strings.Index(cleanLine, ":")
		if colonIdx > 0 {
			key := strings.TrimSpace(cleanLine[:colonIdx])
			val := strings.TrimSpace(cleanLine[colonIdx+1:])
			headers[key] = val

			// Check for Host header (case-insensitive)
			if strings.ToLower(key) == "host" {
				host = val
			}
		}

		if err == io.EOF {
			break
		}
	}

	// 3. Parse Body
	body, _ := io.ReadAll(reader)

	// 4. Construct URL
	// If targetURL is provided via flag, use its scheme and host, but prefer path from request?
	// Or if targetURL is NOT provided, try to build from Host header.

	var finalURL *url.URL

	if targetURL != "" {
		// If user provided -u, use that as base.
		u, err := url.Parse(targetURL)
		if err != nil {
			return nil, fmt.Errorf("invalid target URL: %v", err)
		}

		// If the raw request path is absolute, use it. checking if it starts with http
		// But usually raw request path is relative like /admin

		finalURL = u // start with base
		// Update path from request
		// If u.Path is empty, usually we use the one from request.
		// If request path is just /, and user provided /admin, maybe user wants /admin?
		// Usually raw request file implies the specific endpoint to test.
		// So we overwrite the path.

		if len(path) > 0 {
			// Handle if path is full URL
			if strings.HasPrefix(path, "http") {
				u2, err := url.Parse(path)
				if err == nil {
					finalURL = u2
				}
			} else {
				finalURL.Path = path
			}
		}
	} else {
		// Try to construct from Host header
		if host == "" {
			return nil, fmt.Errorf("no Host header found in request file and no -u URL provided")
		}
		host = strings.TrimSpace(host)

		// Default to https
		scheme := "https"

		// Ensure path starts with /
		if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "http") {
			path = "/" + path
		}

		rawURL := fmt.Sprintf("%s://%s%s", scheme, host, path)
		finalURL, err = url.Parse(rawURL)
		if err != nil {
			return nil, err
		}
	}

	return &ParsedRequest{
		Method:  method,
		URL:     finalURL,
		Headers: headers,
		Body:    body,
	}, nil
}
