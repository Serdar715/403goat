package bypass

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"

	"github.com/Serdar715/403goat/internal/utils"
)

// GeneratePayloadsByMode creates a list of payloads based on the configuration configuration.
func GeneratePayloadsByMode(cfg utils.Config, path string) []string {
	var payloads []string

	prefixes := utils.TopPrefixes
	suffixes := utils.TopSuffixes

	if cfg.PrefixFile != "" {
		prefixes = LoadFromFile(cfg.PrefixFile)
	}
	if cfg.SuffixFile != "" {
		suffixes = LoadFromFile(cfg.SuffixFile)
	}

	// Load from PayloadDir if specified
	if cfg.PayloadDir != "" {
		// Prefixes / Midpaths
		prefixFiles := []string{"prefixes.txt", "midpaths.txt", "midpaths"}
		for _, f := range prefixFiles {
			pPath := filepath.Join(cfg.PayloadDir, f)
			if _, err := os.Stat(pPath); err == nil {
				filePrefixes := LoadFromFile(pPath)
				prefixes = append(prefixes, filePrefixes...)
			}
		}

		// Suffixes / Endpaths
		suffixFiles := []string{"suffixes.txt", "endpaths.txt", "endpaths"}
		for _, f := range suffixFiles {
			sPath := filepath.Join(cfg.PayloadDir, f)
			if _, err := os.Stat(sPath); err == nil {
				fileSuffixes := LoadFromFile(sPath)
				suffixes = append(suffixes, fileSuffixes...)
			}
		}
	}

	// 1. Original
	payloads = append(payloads, path)
	if !strings.HasPrefix(path, "/") {
		payloads = append(payloads, "/"+path)
	}

	// 2. Prefixes
	for _, p := range prefixes {
		// Clean handling of creating path variation
		// logic: trim slash from prefix end, add slash, trim slash from path start
		constructed := strings.TrimRight(p, "/") + "/" + strings.TrimLeft(path, "/")
		payloads = append(payloads, constructed)
	}

	// 3. Suffixes
	for _, s := range suffixes {
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

	payloads = DeduplicatePayloads(payloads)

	if cfg.LimitPayloads > 0 && len(payloads) > cfg.LimitPayloads {
		payloads = payloads[:cfg.LimitPayloads]
	}

	return payloads
}

// LoadFromFile reads lines from a file, ignoring comments and empty lines.
func LoadFromFile(path string) []string {
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

// LoadExtraHeadersAndIPs loads headers.txt and ips.txt from PayloadDir
func LoadExtraHeadersAndIPs(cfg utils.Config) ([]string, []string) {
	var headers []string
	var ips []string

	if cfg.PayloadDir != "" {
		// Headers
		headerFiles := []string{"headers.txt", "headers"}
		for _, f := range headerFiles {
			hPath := filepath.Join(cfg.PayloadDir, f)
			if _, err := os.Stat(hPath); err == nil {
				fileHeaders := LoadFromFile(hPath)
				headers = append(headers, fileHeaders...)
			}
		}

		// IPs
		ipFiles := []string{"ips.txt", "ips"}
		for _, f := range ipFiles {
			iPath := filepath.Join(cfg.PayloadDir, f)
			if _, err := os.Stat(iPath); err == nil {
				fileIPs := LoadFromFile(iPath)
				ips = append(ips, fileIPs...)
			}
		}
	}
	return headers, ips
}

// DeduplicatePayloads removes duplicate strings from the slice.
func DeduplicatePayloads(payloads []string) []string {
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
