package utils

import "time"

type Config struct {
	URL                      string
	Verbose                  int
	Threads                  int
	Delay                    int
	Timeout                  int
	PrefixFile               string
	SuffixFile               string
	OutputFile               string
	NoVerify                 bool
	ProxyURL                 string
	DoublePayloads           bool
	JSONOutput               bool
	RandomParam              bool
	ShowProgress             bool
	LimitPayloads            int
	FilterCodes              []int
	MatchCodes               []int
	FilterSize               int64
	MatchRegex               string
	RateLimit                int
	DebugRequest             bool
	RequestFile              string
	CustomHeaders            []string
	WordlistFile             string
	URLListFile              string
	EnableUnicode            bool
	EnableCase               bool
	EnableDouble             bool
	AutoCalibration          bool
	AutoCalibrationTolerance int64
	NoRedirects              bool
	PayloadDir               string
	// New features inspired by nomore403
	CustomBypassIP     string   // Custom IP for bypass headers (-i)
	Techniques         []string // Specific techniques to use (-k)
	UniqueResults      bool     // Filter duplicate results (--unique)
	EnableMethodCase   bool     // Enable verb case switching
	EnableHTTPVersions bool     // Enable HTTP version fuzzing
}

type Result struct {
	Method         string            `json:"method"`
	StatusCode     int               `json:"status_code"`
	ContentLen     int64             `json:"content_length"`
	Headers        map[string]string `json:"headers"`
	Payload        string            `json:"payload"`
	URL            string            `json:"url"`
	Response       string            `json:"response,omitempty"`
	Time           time.Duration     `json:"response_time"`
	RedirectURL    string            `json:"redirect_url,omitempty"`
	RedirectStatus int               `json:"redirect_status,omitempty"`
	Technique      string            `json:"technique,omitempty"`
	HTTPVersion    string            `json:"http_version,omitempty"`
}
