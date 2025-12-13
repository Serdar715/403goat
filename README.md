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

**403goat** is a high-performance, professional-grade tool designed to automate the discovery of 403 Forbidden and 401 Unauthorized bypass vulnerabilities. It systematically tests path manipulations, HTTP methods, and header injections to identify access control misconfigurations.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔀 **Path Fuzzing** | Tests URL path variations using prefixes (`/%2e/`, `/../`) and suffixes (`.json`, `..;/`) |
| 📨 **Method Fuzzing** | Attempts bypass using different HTTP methods (GET, POST, PUT, DELETE, OPTIONS) |
| 🎭 **Header Injection** | Injects bypass headers like `X-Forwarded-For`, `X-Original-URL`, `X-Custom-IP-Authorization` |
| 📄 **Request File Support** | Load raw HTTP requests from Burp Suite or Caido with full header/cookie preservation |
| 🔌 **Proxy Support** | Route traffic through Burp Suite, OWASP ZAP, or any HTTP proxy |
| ⚡ **High Performance** | Concurrent scanning with configurable thread count |
| 📊 **JSON Output** | Machine-readable output for automation and reporting |

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

Save a raw HTTP request to a file and use it:

```bash
403goat -r request.txt
```

**Example `request.txt` format:**
```http
GET /admin HTTP/1.1
Host: target.com
Cookie: session=abc123
User-Agent: Mozilla/5.0

```
> ⚠️ **Important:** The request file must have a blank line after headers.

### Filter Unwanted Status Codes

```bash
403goat -u https://target.com/admin -fc 403,404,500
```

### Verbose Output

```bash
403goat -u https://target.com/admin -v 1
```

## ⚙️ Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | Target URL | - |
| `-r` | Load raw HTTP request from file | - |
| `-threads` | Number of concurrent threads | 15 |
| `-delay` | Delay between requests (ms) | 50 |
| `-timeout` | Request timeout (seconds) | 10 |
| `-proxy` | HTTP/HTTPS proxy URL | - |
| `-fc` | Filter status codes (comma-separated) | - |
| `-o` | Output file path | results.json |
| `-json` | Enable JSON output format | false |
| `-v` | Verbose level (0, 1, 2) | 0 |
| `-prefix` | Custom prefix wordlist file | - |
| `-suffix` | Custom suffix wordlist file | - |

## 🔬 How It Works

403goat performs three distinct types of tests, each isolated to pinpoint the exact bypass technique:

1. **Path Fuzzing:** Modifies the URL path with known bypass patterns
   - `/%2e/admin`, `/./admin`, `//admin`, `/admin/..;/`

2. **Method Fuzzing:** Tests the endpoint with different HTTP verbs
   - `POST /admin`, `PUT /admin`, `DELETE /admin`

3. **Header Injection:** Adds bypass headers one at a time
   - `X-Forwarded-For: 127.0.0.1`
   - `X-Original-URL: /admin`
   - `X-Custom-IP-Authorization: localhost`

## 📋 Example Output

```
[200] GET /%2e/admin - https://target.com/%2e/admin
[200] GET /admin - https://target.com/admin (Header: X-Forwarded-For: 127.0.0.1)
[403] POST /admin - https://target.com/admin
```

## 🛡️ Disclaimer

This tool is intended for **authorized security testing** and **educational purposes only**.

- ✅ Use on systems you own or have explicit written permission to test
- ❌ Do NOT use on systems without authorization
- ⚖️ The author is not responsible for any misuse of this tool

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by various 403 bypass techniques discovered by the security community
- Built with ❤️ for bug bounty hunters and penetration testers

---

<p align="center">
  <b>Made with 🐐 by <a href="https://github.com/Serdar715">Serdar715</a></b>
</p>
