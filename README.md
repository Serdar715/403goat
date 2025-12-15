<p align="center">
  <img src="https://img.shields.io/badge/🐐-403GOAT-FF0000?style=for-the-badge&labelColor=000000" alt="403goat"/>
</p>

<h1 align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&weight=800&size=35&duration=3000&pause=1000&color=FF0000&center=true&vCenter=true&width=600&lines=403GOAT;Advanced+403+Bypass+Tool;Enterprise+Security+Scanner" alt="Typing SVG" />
</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-FF0000?style=flat-square&logo=go&logoColor=white" alt="Go"/>
  <img src="https://img.shields.io/badge/Version-2.0.0-FF0000?style=flat-square" alt="Version"/>
  <img src="https://img.shields.io/badge/License-MIT-white?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/Platform-Cross--Platform-white?style=flat-square" alt="Platform"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Security-Focused-FF0000?style=flat-square" alt="Security"/>
  <img src="https://img.shields.io/badge/Bypass-928+_Payloads-white?style=flat-square" alt="Payloads"/>
  <img src="https://img.shields.io/badge/Performance-High--Speed-FF0000?style=flat-square" alt="Performance"/>
</p>

---

<p align="center">
  <b>🔴 Enterprise-Grade 403/401 Access Control Bypass Scanner 🔴</b>
</p>

<p align="center">
  <i>Automated discovery of access control misconfigurations with 10+ bypass technique categories</i>
</p>

---

## 🎯 Overview

**403goat** is a high-performance security testing tool designed for penetration testers and security researchers. It automates the discovery of **403 Forbidden** and **401 Unauthorized** bypass vulnerabilities through systematic testing of multiple attack vectors.

```
┌─────────────────────────────────────────────────────────────────┐
│                         403GOAT v2.0.0                          │
├─────────────────────────────────────────────────────────────────┤
│  ► Path Fuzzing         ► Header Injection    ► Host Attacks   │
│  ► Method Fuzzing       ► Method Override     ► Cache Deception│
│  ► Unicode Bypass       ► Content-Type        ► Accept Header  │
│  ► Double Encoding      ► Path Normalization  ► Case Variation │
└─────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Quick Start

```bash
git clone https://github.com/Serdar715/403goat.git && cd 403goat && go build -o 403goat . && ./403goat -u https://target.com/admin
```

---

## 🔴 Bypass Techniques

### Core Engine

| Category | Technique | Payloads |
|:---------|:----------|:--------:|
| 🔀 **Path Fuzzing** | URL path manipulation with prefixes/suffixes | `180+` |
| 📨 **Method Fuzzing** | HTTP verb tampering (GET, POST, PUT, DELETE) | `6` |
| 🎭 **Header Injection** | X-Forwarded-For, X-Original-URL, X-Real-IP | `620+` |
| 🔤 **Unicode Bypass** | Unicode encoded path traversal | `15` |
| 🔠 **Case Manipulation** | Case variations (/Admin, /ADMIN) | `Dynamic` |
| 🔄 **Double Encoding** | Double URL encoding (%252e, %252f) | `10` |

### Advanced Techniques

| Category | Technique | Payloads |
|:---------|:----------|:--------:|
| 🌐 **Host Header** | Localhost/internal IP spoofing | `12` |
| 🔧 **Method Override** | X-HTTP-Method-Override headers | `35` |
| 📝 **Content-Type** | JSON, XML, form-data manipulation | `9` |
| 📥 **Accept Header** | Accept header format bypass | `9` |
| 💾 **Cache Deception** | Static file extension appending | `14` |
| 🛤️ **Path Normalization** | Tab, null, backslash, semicolon | `43` |

---

---

## 🔴 Usage Examples

### Basic Scan

```bash
403goat -u https://target.com/admin
```

### With Burp Suite Proxy

```bash
403goat -u https://target.com/admin -proxy http://127.0.0.1:8080
```

### Request File (Burp/Caido Export)

```bash
403goat -r request.txt
```

### Full Attack Mode

```bash
403goat -u https://target.com/admin -unicode -case -double-encode
```

### Custom Headers

```bash
403goat -u https://target.com/admin -H "Cookie: session=abc" -H "Authorization: Bearer token"
```

### Batch Scan

```bash
403goat -l urls.txt -threads 50 -rate 100
```

### Filter Results

```bash
# Only 200 OK
403goat -u https://target.com/admin -mc 200

# Exclude 403,404
403goat -u https://target.com/admin -fc 403,404

# Regex Match
403goat -u https://target.com/admin -mr "Dashboard|Welcome"
```

---

## 🔴 Command Reference

| Flag | Description | Default |
|:-----|:------------|:-------:|
| `-u` | Target URL | - |
| `-r` | Raw HTTP request file | - |
| `-l` | URL list file | - |
| `-w` | Custom wordlist | - |
| `-H` | Custom header (multiple) | - |
| `-t, -threads` | Concurrent threads | `15` |
| `-delay` | Request delay (ms) | `50` |
| `-timeout` | Timeout (seconds) | `10` |
| `-rate` | Rate limit (req/sec) | `0` |
| `-proxy` | Proxy URL | - |
| `-fc` | Filter status codes | - |
| `-mc` | Match status codes | - |
| `-fs` | Filter response size | - |
| `-mr` | Match regex | - |
| `-unicode` | Unicode bypass | `false` |
| `-case` | Case manipulation | `false` |
| `-double-encode` | Double encoding | `false` |
| `-o` | Output file | `results.json` |
| `-json` | JSON output | `false` |
| `-v` | Verbose (0-2) | `0` |

---

## 🔴 Output Example

```
   _  _    ___  _____    ____  ___    _  _____
  | || |  / _ \|___ /   / ___|/ _ \  / \|_   _|
  | || |_| | | | |_ \  | |  _| | | |/ _ \ | |  
  |__   _| |_| |___) | | |_| | |_| / ___ \| |  
     |_|  \___/|____/   \____|\___/_/   \_\_|  

  ================================================
           403 Bypass Scanner v2.0.0
  ================================================
                  Author: XBug0

[INFO] Scan Configuration:
[INFO]   ├─ Path Payloads: 289
[INFO]   ├─ HTTP Methods: 5
[INFO]   ├─ Header Tests: 481
[INFO]   ├─ Method Override: 35
[INFO]   ├─ Host Header: 12
[INFO]   ├─ Content-Type: 9
[INFO]   ├─ Accept Header: 9
[INFO]   ├─ Cache Deception: 14
[INFO]   ├─ Path Normalization: 43
[INFO]   └─ Total Requests: 897
----------------------------------------------------------------
[200] GET /%2e/admin [path] - https://target.com/%2e/admin
[200] GET /admin [header:X-Forwarded-For=127.0.0.1] - https://target.com/admin
[200] GET /admin [host-header:localhost] - https://target.com/admin
[301] GET /admin [path] -> [200] https://target.com/dashboard
----------------------------------------------------------------
[SUCCESS] Scan completed. Potential bypasses found!
```

---

## 🔴 Architecture

```
403goat/
├── main.go                    # Entry point & CLI
├── go.mod                     # Dependencies
├── internal/
│   ├── bypass/
│   │   └── runner.go          # Scan engine
│   └── utils/
│       ├── client.go          # HTTP client
│       ├── logger.go          # Colored logging
│       ├── models.go          # Data structures
│       ├── parser.go          # Request parser
│       └── payloads.go        # Bypass payloads
└── README.md
```

---

## ⚠️ Legal Disclaimer

```
┌─────────────────────────────────────────────────────────────────┐
│                         ⚠️ WARNING ⚠️                           │
├─────────────────────────────────────────────────────────────────┤
│  This tool is intended for AUTHORIZED security testing only.   │
│                                                                 │
│  ✓ Use on systems you own                                      │
│  ✓ Use with explicit written permission                        │
│  ✗ Do NOT use on systems without authorization                 │
│                                                                 │
│  The author is NOT responsible for any misuse of this tool.    │
└─────────────────────────────────────────────────────────────────┘
```

---

<p align="center">
  <img src="https://img.shields.io/badge/Made_with-🐐-FF0000?style=for-the-badge&labelColor=000000" alt="Made with Goat"/>
</p>

<p align="center">
  <b>Developed by <a href="https://github.com/Serdar715">XBug0</a></b>
</p>

<p align="center">
  <a href="https://github.com/Serdar715/403goat">
    <img src="https://img.shields.io/badge/⭐_Star_This_Repo-FF0000?style=for-the-badge&labelColor=000000" alt="Star"/>
  </a>
</p>

