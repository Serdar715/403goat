# 🐐 403goat

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/github/go-mod/go-version/Serdar715/403goat)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)

**403goat** is a professional, advanced 403/401 Forbidden/Unauthorized bypass tool written in Go. It automates testing of headers, paths, and methods to bypass access controls.

## 📦 Installation (One-Liner)

Copy and run this command to install and verify 403goat globally:

```bash
git clone https://github.com/Serdar715/403goat.git && cd 403goat && go build -o 403goat main.go && sudo mv 403goat /usr/local/bin/
```

Now you can run **403goat** from anywhere in your terminal.

## 🛠️ Usage

### Basic Scan
```bash
403goat -u https://target.com/admin
```

### Advanced Scan (Proxy + Threads)
```bash
403goat -u https://target.com/admin -threads 25 -proxy http://127.0.0.1:8080
```

### Using a Request File (Burp/Caido)
```bash
403goat -r req.txt
```

### Options
```txt
  -u string        Target URL
  -r string        Load raw HTTP request from file
  -threads int     Number of concurrent threads (default 15)
  -delay int       Delay between requests in ms (default 50)
  -proxy string    Upstream proxy URL
  -double          Enable double payload generation
  -random          Append random parameters
  -json            Enable JSON output
  -o string        Output file path (default "results.json")
  -fc string       Filter status codes (e.g., 403,404)
```

## 🛡️ Disclaimer

This tool is for educational purposes and authorized penetration testing only. Do not use this tool on systems you do not have permission to test.

## 📄 License

Distributed under the MIT License.
