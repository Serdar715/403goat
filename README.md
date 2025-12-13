# 🐐 403goat

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/github/go-mod/go-version/Serdar715/403goat)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)

**403goat** is a professional, streamlined 403/401 Forbidden/Unauthorized bypass tool written in Go. It focuses on testing critical headers, standard HTTP methods, and path permutations efficiently to bypass ACLs and WAFs.

> **Disclaimer**: This tool is for educational purposes and authorized penetration testing only. Do not use this tool on systems you do not have explicit permission to test.

## 🚀 Features

*   **Header Manipulation**: Automates checking of key headers like `X-Forwarded-For`, `X-Original-URL`, etc.
*   **Path Fuzzing**: Smart permutations with specific prefixes and suffixes known to bypass restrictions.
*   **Raw Request Support**: Load full HTTP requests from files (Burp Suite, Caido support).
*   **Proxy Support**: Route traffic through HTTP/HTTPS proxies.
*   **Performance**: Fast,concurrent scanning with configurable thread control.
*   **Reporting**: Clean CLI output and optional JSON logging.

## 📦 Installation

Ensure you have **Go 1.19+** installed.

```bash
git clone https://github.com/Serdar715/403goat.git
cd 403goat
go build -o 403goat main.go
```

## 🛠️ Usage

### Basic Scan
```bash
./403goat -u https://target.com/admin
```

### Advanced Scan with Proxy
```bash
./403goat -u https://target.com/admin -threads 20 -proxy http://127.0.0.1:8080
```

### Using a Request File (Recommended)
Save a raw request from Burp Suite to `req.txt`:
```bash
./403goat -r req.txt
```

### Flags
```txt
  -u string
        Target URL
  -r string
        Load raw HTTP request from file
  -threads int
        Number of concurrent threads (default 15)
  -delay int
        Delay between requests in ms (default 50)
  -proxy string
        Upstream proxy URL (e.g., http://127.0.0.1:8080)
  -double
        Enable double payload generation (Prefix + Path + Suffix)
  -random
        Append random parameters to requests
  -json
        Enable JSON output
  -o string
        Output file path (default "results.json")
  -fc string
        Filter status codes (e.g., 403,404)
```

## 🛡️ Legal

This tool is designed for security professionals to test their own systems or systems they are authorized to test. The author is not responsible for any misuse.

## 🤝 Contributing

Contributions are welcome! Please submit a Pull Request.

## 📄 License

Distributed under the MIT License.
