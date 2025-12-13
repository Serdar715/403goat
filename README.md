# 🐐 403goat

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.19+-00ADD8?style=for-the-badge&logo=go" alt="Go Version"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=for-the-badge" alt="Platform"/>
</p>

<p align="center">
  <b>Advanced 403/401 Bypass Tool for Security Researchers</b>
</p>

---

**403goat** is a high-performance, professional-grade tool designed to automate the discovery of 403 Forbidden and 401 Unauthorized bypass vulnerabilities. It systematically tests path manipulations, HTTP methods, header injections, Unicode encoding, and more to identify access control misconfigurations.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔀 **Path Fuzzing** | Tests URL path variations using prefixes (`/%2e/`, `/../`) and suffixes (`.json`, `..;/`) |
| 📨 **Method Fuzzing** | Attempts bypass using different HTTP methods (GET, POST, PUT, DELETE, OPTIONS) |
| 🎭 **Header Injection** | Injects bypass headers like `X-Forwarded-For`, `X-Original-URL`, `X-Custom-IP-Authorization` |
| 🔤 **Unicode Bypass** | Tests Unicode encoded characters (`%c0%af`, `%ef%bc%8f`) for path traversal |
| 🔠 **Case Manipulation** | Tests `/Admin`, `/ADMIN`, `/aDmIn` variations |
| 🔄 **Double Encoding** | Tests `%252e`, `%252f` double URL encoded payloads |
| 📄 **Request File Support** | Load raw HTTP requests from Burp Suite or Caido with full header/cookie preservation |
| 🔌 **Proxy Support** | Route traffic through Burp Suite, OWASP ZAP, or any HTTP proxy |
| ⚡ **High Performance** | Concurrent scanning with configurable thread count and rate limiting |
| 📊 **Advanced Filtering** | Filter by status code, response size, or regex match |
| 📁 **Multiple URL Scan** | Scan multiple URLs from a file |
| 📝 **Custom Wordlist** | Use your own wordlist for path fuzzing |

## 📦 Installation

### One-Line Install (Recommended)

```bash
git clone https://github.com/Serdar715/403goat.git && cd 403goat && go build -o 403goat . && sudo mv 403goat /usr/local/bin/
```

### Manual Build

```bash
git clone https://github.com/Serdar715/403goat.git
cd 403goat
go build -o 403goat .
./403goat -h
```

## 🚀 Usage

### Basic Scan

```bash
403goat -u https://target.com/admin
```

### With Proxy (Burp Suite)

```bash
403goat -u https://target.com/admin -proxy http://127.0.0.1:8080
```

### Using Request File (Burp/Caido Export)

```bash
403goat -r request.txt
```

### Enable All Bypass Techniques

```bash
403goat -u https://target.com/admin -unicode -case -double-encode
```

### Custom Wordlist

```bash
403goat -u https://target.com/admin -w custom_paths.txt
```

### Multiple URL Scan

```bash
403goat -l urls.txt -threads 25
```

### Filter & Match Options

```bash
# Only show 200 responses
403goat -u https://target.com/admin -mc 200

# Filter out 403 and 404
403goat -u https://target.com/admin -fc 403,404

# Filter by response size
403goat -u https://target.com/admin -fs 1234

# Match regex in response
403goat -u https://target.com/admin -mr "Welcome|Dashboard"
```

### Rate Limiting

```bash
403goat -u https://target.com/admin -rate 100
```

## ⚙️ Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | Target URL | - |
| `-r` | Load raw HTTP request from file | - |
| `-l` | File containing list of URLs to scan | - |
| `-w` | Custom wordlist file for paths | - |
| `-threads` | Number of concurrent threads | 15 |
| `-delay` | Delay between requests (ms) | 50 |
| `-timeout` | Request timeout (seconds) | 10 |
| `-rate` | Rate limit (requests/second) | 0 (unlimited) |
| `-proxy` | HTTP/HTTPS proxy URL | - |
| `-H` | Custom header (can be used multiple times) | - |
| `-fc` | Filter status codes (comma-separated) | - |
| `-mc` | Match status codes (comma-separated) | - |
| `-fs` | Filter response size | - |
| `-mr` | Match regex in response body | - |
| `-unicode` | Enable Unicode bypass payloads | false |
| `-case` | Enable case manipulation payloads | false |
| `-double-encode` | Enable double URL encoding | false |
| `-o` | Output file path | results.json |
| `-json` | Enable JSON output format | false |
| `-v` | Verbose level (0, 1, 2) | 0 |

## 🔬 How It Works

403goat performs isolated tests to pinpoint the exact bypass technique:

### 1. Path Fuzzing
Modifies the URL path with known bypass patterns:
- `/%2e/admin`, `/./admin`, `//admin`, `/admin/..;/`

### 2. Method Fuzzing
Tests the endpoint with different HTTP verbs:
- `POST /admin`, `PUT /admin`, `DELETE /admin`, `OPTIONS /admin`

### 3. Header Injection
Adds bypass headers one at a time:
- `X-Forwarded-For: 127.0.0.1`
- `X-Original-URL: /admin`
- `X-Custom-IP-Authorization: localhost`

### 4. Unicode Bypass (with `-unicode`)
Tests Unicode encoded path traversal:
- `/%c0%af/admin` (Unicode slash)
- `/%c0%ae/admin` (Unicode dot)
- `/%ef%bc%8f/admin` (Fullwidth slash)

### 5. Case Manipulation (with `-case`)
Tests case variations:
- `/Admin`, `/ADMIN`, `/aDmIn`, `/AdMiN`

### 6. Double Encoding (with `-double-encode`)
Tests double URL encoding:
- `/%252e/admin`, `/%252e%252e/admin`, `/%252f/admin`

## 📋 Example Output

```
[INFO] Scan Configuration:
[INFO]   ├─ Path Payloads: 180
[INFO]   ├─ HTTP Methods: 6
[INFO]   ├─ Header Tests: 620
[INFO]   └─ Total Requests: 809

[200] GET /%2e/admin [path] - https://target.com/%2e/admin
[200] GET /admin [header:X-Forwarded-For=127.0.0.1] - https://target.com/admin
[301] GET /admin [path] - https://target.com/admin -> [200] https://target.com/dashboard
```

## 🛡️ Disclaimer

This tool is intended for **authorized security testing** and **educational purposes only**.

- ✅ Use on systems you own or have explicit written permission to test
- ❌ Do NOT use on systems without authorization
- ⚖️ The author is not responsible for any misuse of this tool

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>Made with 🐐 by <a href="https://github.com/Serdar715">Serdar715</a></b>
</p>
