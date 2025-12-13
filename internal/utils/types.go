package utils

import "time"

type Config struct {
	URL            string
	Verbose        int
	Threads        int
	Delay          int
	Timeout        int
	PrefixFile     string
	SuffixFile     string
	OutputFile     string
	NoVerify       bool
	ProxyURL       string
	DoublePayloads bool
	JSONOutput     bool
	RandomParam    bool
	ShowProgress   bool
	LimitPayloads  int
	FilterCodes    []int
	DebugRequest   bool
	RequestFile    string
	CustomHeaders  []string
}

type Result struct {
	Method         string            `json:"method"`
	StatusCode     int               `json:"status_code"`
	ContentLen     int64             `json:"content_length"`
	Headers        map[string]string `json:"headers"`
	Payload        string            `json:"payload"`
	URL            string            `json:"url"`
	Response       string            `json:"response"`
	Time           time.Duration     `json:"response_time"`
	RedirectURL    string            `json:"redirect_url,omitempty"`
	RedirectStatus int               `json:"redirect_status,omitempty"`
	Technique      string            `json:"technique,omitempty"`
}
