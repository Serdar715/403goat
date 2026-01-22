package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Serdar715/403goat/internal/bypass"
	"github.com/Serdar715/403goat/internal/utils"

	"github.com/fatih/color"
)

func main() {
	cfg := parseFlags()
	utils.PrintBanner()

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		utils.LogInfo("\n\nUser interrupted. Shutting down gracefully...")
		cancel()
	}()
	defer cancel()

	// 1. Collect Targets
	var targets []string

	// From -u
	if cfg.URL != "" {
		targets = append(targets, cfg.URL)
	}

	// From -l (URL List)
	if cfg.URLListFile != "" {
		lines, err := loadLines(cfg.URLListFile)
		if err == nil {
			targets = append(targets, lines...)
		} else {
			utils.LogError("Failed to load URL list: %v", err)
		}
	}

	// From Stdin
	if isStdin() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				targets = append(targets, line)
			}
		}
	}

	// Check if RequestFile is used (special case) or we have targets
	if len(targets) == 0 && cfg.RequestFile == "" {
		fmt.Println("Usage: 403goat [OPTIONS] <URL> or pipe URLs to stdin")
		flag.PrintDefaults()
		os.Exit(1)
	}

	client := utils.NewHTTPClient(cfg.Timeout, cfg.ProxyURL)
	var allResults []utils.Result
	var anyFound bool

	// If RequestFile is present, it usually overrides URL targets or is run independently.
	// For simplicity, if RequestFile IS present, we run it and ignore other targets (standard behavior for -r).
	if cfg.RequestFile != "" {
		runSingleScan(ctx, cfg, client, &allResults, &anyFound)
	} else {
		// Run for each target
		for _, t := range targets {
			// Check context between targets
			select {
			case <-ctx.Done():
				break
			default:
			}

			// Normalize URL
			if !strings.HasPrefix(t, "http") {
				t = "https://" + t
			}

			targetCfg := cfg
			targetCfg.URL = t

			utils.LogInfo("\nScanning Target: %s", t)
			runSingleScan(ctx, targetCfg, client, &allResults, &anyFound)
		}
	}

	if anyFound {
		utils.LogSuccess("\nScan completed. Potential bypasses found!")
	} else {
		utils.LogInfo("\nScan completed. No bypasses found.")
	}

	if cfg.OutputFile != "" {
		saveResults(allResults, cfg)
	}
}

func runSingleScan(ctx context.Context, cfg utils.Config, client *http.Client, allResults *[]utils.Result, anyFound *bool) {
	runner, err := bypass.NewRunner(cfg, client)
	if err != nil {
		utils.LogError("Failed to initialize runner for %s: %v", cfg.URL, err)
		return
	}

	go runner.Run(ctx)

	foundLocal := false
	for res := range runner.Results {
		isSuccess := (res.StatusCode >= 200 && res.StatusCode < 300) || res.StatusCode >= 300 && res.StatusCode < 400

		*allResults = append(*allResults, res)

		if isSuccess {
			foundLocal = true
			*anyFound = true
			statusColor := color.GreenString
			if res.StatusCode >= 300 {
				statusColor = color.YellowString
			}

			techniqueStr := ""
			if res.Technique != "" {
				techniqueStr = fmt.Sprintf(" [%s]", color.HiBlueString(res.Technique))
			}
			output := fmt.Sprintf("[%s] %s %s%s - %s", statusColor("%d", res.StatusCode), color.CyanString(res.Method), color.MagentaString(res.Payload), techniqueStr, res.URL)

			if res.RedirectURL != "" {
				redirectColor := color.GreenString
				if res.RedirectStatus >= 400 {
					redirectColor = color.RedString
				} else if res.RedirectStatus >= 300 {
					redirectColor = color.YellowString
				}
				output += fmt.Sprintf(" -> [%s] %s", redirectColor("%d", res.RedirectStatus), res.RedirectURL)
			}

			fmt.Println(output)
		} else if cfg.Verbose >= 1 {
			techStr := ""
			if res.Technique != "" {
				techStr = fmt.Sprintf(" %s", color.HiBlackString("(%s)", res.Technique))
			}
			fmt.Printf("[%s] %s %s%s - %s\n", color.RedString("%d", res.StatusCode), color.CyanString(res.Method), color.MagentaString(res.Payload), techStr, res.URL)
		}
	}

	if foundLocal {
		// Just to separate visually if needed, but not printing "Bypasses Found!" every time
	}
}

// Helper to check if stdin has data
func isStdin() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) == 0
}

func loadLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
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
	return lines, nil
}

func parseFlags() utils.Config {
	cfg := utils.Config{}

	var filterCodesStr string
	var matchCodesStr string

	flag.StringVar(&cfg.URL, "u", "", "Target URL")
	flag.BoolVar(&cfg.JSONOutput, "json", false, "JSON output")
	flag.IntVar(&cfg.Verbose, "v", 0, "Verbose (0|1|2)")
	flag.IntVar(&cfg.Threads, "threads", 15, "Number of threads")
	flag.IntVar(&cfg.Threads, "t", 15, "Number of threads (alias for -threads)")
	flag.IntVar(&cfg.Delay, "delay", 50, "Delay between requests (ms)")
	flag.IntVar(&cfg.Timeout, "timeout", 10, "Timeout (seconds)")
	flag.StringVar(&cfg.PrefixFile, "prefix", "", "Custom prefix file")
	flag.StringVar(&cfg.SuffixFile, "suffix", "", "Custom suffix file")
	flag.StringVar(&cfg.PayloadDir, "payload-dir", "", "Custom payload directory (prefixed.txt, suffixes.txt)")
	flag.StringVar(&cfg.RequestFile, "r", "", "Load raw HTTP request from file")
	flag.StringVar(&cfg.OutputFile, "o", "results.json", "Output file")
	flag.BoolVar(&cfg.NoVerify, "no-verify", true, "Skip SSL verification (default true)")
	flag.StringVar(&cfg.ProxyURL, "proxy", "", "HTTP proxy")
	flag.BoolVar(&cfg.DoublePayloads, "double", false, "Combine prefix+suffix")
	flag.BoolVar(&cfg.RandomParam, "random", false, "Add random param")
	flag.BoolVar(&cfg.ShowProgress, "progress", true, "Show progress bar")
	flag.IntVar(&cfg.LimitPayloads, "limit", 0, "Limit payloads (0=unlimited)")
	flag.StringVar(&filterCodesStr, "fc", "", "Filter status codes (comma-separated)")
	flag.StringVar(&matchCodesStr, "mc", "", "Match status codes (comma-separated)")
	flag.Int64Var(&cfg.FilterSize, "fs", 0, "Filter response size")
	flag.StringVar(&cfg.MatchRegex, "mr", "", "Match regex in response body")
	flag.IntVar(&cfg.RateLimit, "rate", 0, "Rate limit (requests/second, 0=unlimited)")
	flag.BoolVar(&cfg.DebugRequest, "debug", false, "Show raw HTTP request/response details")
	flag.StringVar(&cfg.WordlistFile, "w", "", "Custom wordlist file for paths")
	flag.StringVar(&cfg.URLListFile, "l", "", "File containing list of URLs to scan")
	flag.BoolVar(&cfg.EnableUnicode, "unicode", false, "Enable Unicode bypass payloads")
	flag.BoolVar(&cfg.EnableCase, "case", false, "Enable case manipulation payloads")
	flag.BoolVar(&cfg.EnableDouble, "double-encode", false, "Enable double URL encoding")
	flag.BoolVar(&cfg.AutoCalibration, "ac", false, "Enable auto-calibration (filter false positives)")
	flag.Int64Var(&cfg.AutoCalibrationTolerance, "act", 10, "Auto-calibration tolerance in bytes (default 10)")
	flag.BoolVar(&cfg.NoRedirects, "no-redirect", false, "Disable following redirects")

	// New features inspired by nomore403
	flag.StringVar(&cfg.CustomBypassIP, "i", "", "Custom IP for bypass headers (e.g., 8.8.8.8)")
	var techniquesStr string
	flag.StringVar(&techniquesStr, "k", "", "Specific techniques to use (comma-separated: path,method,header,version,cache)")
	flag.BoolVar(&cfg.UniqueResults, "unique", false, "Filter duplicate results")
	flag.BoolVar(&cfg.EnableMethodCase, "method-case", false, "Enable verb case switching (gEt, GeT)")
	flag.BoolVar(&cfg.EnableHTTPVersions, "http-versions", false, "Enable HTTP version fuzzing (1.0, 1.1, 2)")

	// Custom headers flag - can be used multiple times
	var customHeaders headerFlags
	flag.Var(&customHeaders, "H", "Custom header (can be used multiple times, e.g., -H 'Cookie: xxx')")

	flag.Parse()

	cfg.CustomHeaders = customHeaders

	// Parse techniques
	if techniquesStr != "" {
		cfg.Techniques = strings.Split(techniquesStr, ",")
	}

	// If a non-flag argument is provided, treat it as URL if -u is empty
	if cfg.URL == "" && len(flag.Args()) > 0 {
		cfg.URL = flag.Arg(0)
	}
	// Note: We don't enforce scheme here immediately because we do it in the loop for each target

	// Parse filter codes
	if filterCodesStr != "" {
		codes := strings.Split(filterCodesStr, ",")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if num, err := strconv.Atoi(code); err == nil {
				cfg.FilterCodes = append(cfg.FilterCodes, num)
			}
		}
	}

	// Parse match codes
	if matchCodesStr != "" {
		codes := strings.Split(matchCodesStr, ",")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if num, err := strconv.Atoi(code); err == nil {
				cfg.MatchCodes = append(cfg.MatchCodes, num)
			}
		}
	}

	return cfg
}

// Custom flag type for multiple -H flags
type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func saveResults(results []utils.Result, cfg utils.Config) {
	f, err := os.Create(cfg.OutputFile)
	if err != nil {
		utils.LogError("Could not create output file: %v", err)
		return
	}
	defer f.Close()

	if cfg.JSONOutput {
		encoder := json.NewEncoder(f)
		encoder.SetIndent("", "  ")
		encoder.Encode(results)
	} else {
		for _, r := range results {
			f.WriteString(fmt.Sprintf("[%d] %s %s\nPayload: %s\nURL: %s\n\n", r.StatusCode, r.Method, r.Payload, r.Payload, r.URL))
		}
	}
	utils.LogSuccess("Results saved to %s", cfg.OutputFile)
}
