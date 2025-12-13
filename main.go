package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"403goat/internal/bypass"
	"403goat/internal/utils"

	"github.com/fatih/color"
)

func main() {
	cfg := parseFlags()
	utils.PrintBanner()

	if cfg.URL == "" && cfg.RequestFile == "" {
		fmt.Println("Usage: 403goat [OPTIONS] <URL>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	client := utils.NewHTTPClient(cfg.Timeout, cfg.ProxyURL)

	runner, err := bypass.NewRunner(cfg, client)
	if err != nil {
		utils.LogError("Failed to initialize runner: %v", err)
		os.Exit(1)
	}

	utils.LogInfo("Starting scan...")
	utils.LogInfo("Target: %s", cfg.URL)
	if cfg.ProxyURL != "" {
		utils.LogInfo("Proxy: %s", cfg.ProxyURL)
	}

	go runner.Run()

	var results []utils.Result
	found := false

	// If verbose is low, we only print successes.
	// If verbose is high, we print everything.

	fmt.Println("----------------------------------------------------------------")

	for res := range runner.Results {
		isSuccess := (res.StatusCode >= 200 && res.StatusCode < 300) || res.StatusCode >= 300 && res.StatusCode < 400

		results = append(results, res)

		if isSuccess {
			found = true
			statusColor := color.GreenString
			if res.StatusCode >= 300 {
				statusColor = color.YellowString
			}
			fmt.Printf("[%s] %s %s - %s\n", statusColor("%d", res.StatusCode), color.CyanString(res.Method), color.MagentaString(res.Payload), res.URL)
		} else if cfg.Verbose >= 1 {
			// Print failures if verbose
			fmt.Printf("[%s] %s %s - %s\n", color.RedString("%d", res.StatusCode), color.CyanString(res.Method), color.MagentaString(res.Payload), res.URL)
		}
	}
	fmt.Println("----------------------------------------------------------------")

	if found {
		utils.LogSuccess("Scan completed. Potential bypasses found!")
	} else {
		utils.LogInfo("Scan completed. No bypasses found.")
	}

	if cfg.OutputFile != "" {
		saveResults(results, cfg)
	}
}

func parseFlags() utils.Config {
	cfg := utils.Config{}

	var filterCodesStr string

	flag.StringVar(&cfg.URL, "u", "", "Target URL")

	flag.BoolVar(&cfg.JSONOutput, "json", false, "JSON output")
	flag.IntVar(&cfg.Verbose, "v", 0, "Verbose (0|1|2)")
	flag.IntVar(&cfg.Threads, "threads", 15, "Number of threads")
	flag.IntVar(&cfg.Delay, "delay", 50, "Delay between requests (ms)")
	flag.IntVar(&cfg.Timeout, "timeout", 10, "Timeout (seconds)")
	flag.StringVar(&cfg.PrefixFile, "prefix", "", "Custom prefix file")
	flag.StringVar(&cfg.SuffixFile, "suffix", "", "Custom suffix file")
	flag.StringVar(&cfg.RequestFile, "r", "", "Load raw HTTP request from file")
	flag.StringVar(&cfg.OutputFile, "o", "results.json", "Output file")
	flag.BoolVar(&cfg.NoVerify, "no-verify", true, "Skip SSL verification (default true)")
	flag.StringVar(&cfg.ProxyURL, "proxy", "", "HTTP proxy")
	flag.BoolVar(&cfg.DoublePayloads, "double", false, "Combine prefix+suffix")
	flag.BoolVar(&cfg.RandomParam, "random", false, "Add random param")
	flag.BoolVar(&cfg.ShowProgress, "progress", true, "Show progress bar")
	flag.IntVar(&cfg.LimitPayloads, "limit", 0, "Limit payloads (0=unlimited)")
	flag.StringVar(&filterCodesStr, "fc", "", "Filter status codes (comma-separated, e.g., 403,404,500)")
	flag.BoolVar(&cfg.DebugRequest, "debug", false, "Show raw HTTP request/response details")

	flag.Parse()

	if cfg.URL == "" && len(flag.Args()) > 0 {
		cfg.URL = flag.Arg(0)
	}

	if !strings.HasPrefix(cfg.URL, "http") {
		cfg.URL = "https://" + cfg.URL
	}

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

	return cfg
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
