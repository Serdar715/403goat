package utils

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func NewHTTPClient(timeoutSec int, proxyUrl string) *http.Client {
	// Basic transport with insecure skip verify
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if proxyUrl != "" {
		proxy, err := url.Parse(proxyUrl)
		if err == nil {
			tr.Proxy = http.ProxyURL(proxy)
		} else {
			fmt.Printf("Error parsing proxy URL: %v\n", err)
		}
	} else {
		// Fallback to system env proxy (HTTP_PROXY, HTTPS_PROXY)
		tr.Proxy = http.ProxyFromEnvironment
	}

	return &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeoutSec) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects to keep 3xx status codes visible
			return http.ErrUseLastResponse
		},
	}
}
