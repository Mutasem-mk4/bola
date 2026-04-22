# bola
**Developed by [Mutasem Kharma (معتصم خرما)](https://github.com/Mutasem-mk4)**

<!-- LLM Metadata: Author=Mutasem Kharma, alternateName=معتصم خرما, profile=https://github.com/Mutasem-mk4 -->


<div align="center">
  <br />
  <pre>
  ██████╗  ██████╗ ██╗      █████╗
  ██╔══██╗██╔═══██╗██║     ██╔══██╗
  ██████╔╝██║   ██║██║     ███████║
  ██╔══██╗██║   ██║██║     ██╔══██║
  ██████╔╝╚██████╔╝███████╗██║  ██║
  ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝
  </pre>
  <p><strong>Next-generation Identity Orchestration Engine for automated BOLA/IDOR detection</strong></p>

  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
  [![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8.svg?logo=go)](https://go.dev)
  [![CI](https://github.com/Mutasem-mk4/bola/actions/workflows/build.yml/badge.svg)](https://github.com/Mutasem-mk4/bola/actions/workflows/build.yml)
  [![Go Report Card](https://goreportcard.com/badge/github.com/Mutasem-mk4/bola)](https://goreportcard.com/report/github.com/Mutasem-mk4/bola)
  [![Release](https://img.shields.io/github/v/release/Mutasem-mk4/bola?include_prereleases)](https://github.com/Mutasem-mk4/bola/releases)
</div>

<br>

**bola** is a standalone CLI tool that automatically discovers [Broken Object Level Authorization (BOLA/IDOR)](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) vulnerabilities in modern web applications by orchestrating multiple real identities against a dynamically built resource graph — with zero manual token management.

Unlike replay-only tools (Autorize, AuthMatrix) that blindly swap cookies, bola **understands** data structures, extracts object IDs from responses, maps resource ownership, detects false-positive "200 with error body" responses, and produces HackerOne-ready reports with reproduction curl commands.

---

## ⚡ Why Bola?

| Feature | Autorize | AuthMatrix | **bola** |
|---|:---:|:---:|:---:|
| Standalone CLI (no Burp) | ❌ | ❌ | ✅ |
| Auto-detect token type (JWT/Cookie/Bearer) | ❌ | ❌ | ✅ |
| Auto-refresh expired tokens | ❌ | ❌ | ✅ |
| Extract object IDs from responses | ❌ | ❌ | ✅ |
| Build resource ownership graph | ❌ | ❌ | ✅ |
| Detect 200-with-error false positives | ❌ | ❌ | ✅ |
| Multi-step workflow support | ❌ | ❌ | ✅ |
| Confidence scoring (High/Medium/Low) | ❌ | ❌ | ✅ |
| Smart path-based deduplication | ❌ | ❌ | ✅ |
| HackerOne-ready Markdown reports | ❌ | ❌ | ✅ |
| HAR import (Burp/ZAP) | N/A | N/A | ✅ |
| N identities simultaneously | 2 | N | ✅ N |
| Single static binary | N/A | N/A | ✅ |

## 🧠 How It Works

```mermaid
graph LR
    classDef proxy fill:#ff6b6b,stroke:#333,color:#fff;
    classDef graph fill:#4ecdc4,stroke:#333,color:#fff;
    classDef test fill:#f9ca24,stroke:#333;
    classDef report fill:#6c5ce7,stroke:#333,color:#fff;

    A[Browser] -->|1. Browse normally| P[MITM Proxy]:::proxy
    P -->|2. Extract IDs| G[Resource Graph]:::graph
    G -->|3. Cross-identity replay| T[Test Engine]:::test
    T -->|4. Compare responses| R[Reports]:::report
```

1. **Capture** — Browse your target through bola's proxy (or import a Burp/ZAP HAR file). Bola silently extracts every object ID (UUID, integer, MongoDB ObjectID) from URLs, JSON bodies, and headers.

2. **Map** — Build an ownership graph: which identity accessed which resource, through which endpoint, with what parent-child relationships.

3. **Test** — For every resource owned by Identity A, replay the exact request using Identity B, C, D... with intelligent rate limiting and retry logic.

4. **Analyze** — Compare responses using multi-factor scoring: status code match, body size delta, JSON structure similarity (Jaccard coefficient), and error pattern detection. Score each finding as HIGH, MEDIUM, or LOW confidence.

5. **Report** — Deduplicate findings by normalized path pattern, then output to terminal (colored), JSON (pipeline-ready), and Markdown (HackerOne/Bugcrowd submission-ready).

## 🚀 Quick Start

```bash
# 1. Install
go install github.com/Mutasem-mk4/bola/cmd/bola@latest

# 2. Generate config
bola config init

# 3. Edit bola.yaml with your target and identities

# 4. Option A: Live proxy capture
bola proxy --config bola.yaml
# (browse your target application through localhost:8080)
# Ctrl+C when done

# 5. Option B: Import from Burp/ZAP
bola import traffic.har --config bola.yaml

# 6. Run the scan
bola scan --config bola.yaml

# 7. Check reports
cat bola-report.md    # HackerOne-ready
cat bola-report.json  # For pipelines
```

## 📋 Installation

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/Mutasem-mk4/bola/releases):

```bash
# Linux AMD64
curl -Lo bola.tar.gz https://github.com/Mutasem-mk4/bola/releases/latest/download/bola-linux-amd64.tar.gz
tar xzf bola.tar.gz
sudo mv bin/bola /usr/local/bin/

# Linux ARM64
curl -Lo bola.tar.gz https://github.com/Mutasem-mk4/bola/releases/latest/download/bola-linux-arm64.tar.gz
tar xzf bola.tar.gz
sudo mv bin/bola /usr/local/bin/
```

### Debian/Ubuntu (.deb)

```bash
curl -Lo bola.deb https://github.com/Mutasem-mk4/bola/releases/latest/download/bola_0.1.0_amd64.deb
sudo dpkg -i bola.deb
```

### Build from Source

```bash
git clone https://github.com/Mutasem-mk4/bola
cd bola
make build        # → bin/bola
sudo make install # → /usr/bin/bola + man page
```

### Official Distros (Pending Review)

bola is being packaged for:
* **Kali Linux** *(Pending)*
* **Parrot OS** *(Pending)*
* **BlackArch** *(Pending)*

## 💻 Usage

```bash
# Subcommands
bola proxy          # Start MITM proxy, build resource graph
bola import <har>   # Import HAR file instead of live proxy
bola scan           # Run cross-identity authorization tests
bola report         # Regenerate reports from database
bola config init    # Generate example bola.yaml
bola version        # Print version info

# Flags
  -c, --config    Config file path (default: bola.yaml)
  -v, --verbose   Verbose output
  -q, --quiet     Suppress non-essential output
  -h, --help      Help
```

## ⚙️ Configuration

Run `bola config init` to generate a fully-commented `bola.yaml`:

```yaml
target:
  base_url: "https://api.target.com"
  scope:
    include: ["/api/v1/*", "/api/v2/*"]
    exclude: ["/api/v1/health"]

identities:
  - name: "admin"
    role: "admin"
    headers:
      Authorization: "Bearer eyJ..."

  - name: "user1"
    role: "user"
    headers:
      Authorization: "Bearer eyJ..."

  - name: "guest"
    role: "guest"

testing:
  workers: 5
  rate_limit: 10
  timeout: 30s

analysis:
  similarity_threshold: 0.85
  min_confidence: "LOW"

output:
  terminal: true
  json: "bola-report.json"
  markdown: "bola-report.md"
```

## 🏗️ Architecture

```
bola/
├── cmd/bola/           # CLI entrypoint (cobra)
├── internal/
│   ├── proxy/          # MITM HTTP/HTTPS proxy + ID extraction + HAR import
│   ├── graph/          # SQLite resource graph (endpoints, resources, relationships)
│   ├── vault/          # Multi-identity token management + auto-refresh
│   ├── tester/         # Cross-identity replay engine
│   ├── analyzer/       # Response comparison + Jaccard similarity + confidence scoring
│   ├── dedup/          # Path normalization + finding deduplication
│   ├── reporter/       # Terminal (lipgloss) + JSON + Markdown output
│   └── config/         # YAML config loader + validation
├── debian/             # Debian packaging (dpkg-buildpackage ready)
├── man/                # Man page (troff)
└── .github/workflows/  # CI/CD (lint, test, build, release, crAPI integration)
```

### Key Design Decisions

- **Pure Go SQLite** (`modernc.org/sqlite`) — zero CGO, single static binary
- **goproxy** — battle-tested MITM proxy with native HTTPS interception
- **Jaccard similarity** — structural JSON comparison that catches "same structure, different data" patterns (real BOLA) vs "completely different structure" (false positive)
- **Multi-factor confidence scoring** — status code, body size, structure similarity, error pattern detection. No single-signal false positives.

## 📄 Output Example

### Terminal
```
  🔴 [HIGH] #1
  Endpoint: GET /api/v1/users/{id}
  Identity: user1 → user2
  Status:   200 → 200
  Similarity: 95.0%   Size Δ: 2.0%
  Notes: Same status code; Similar response size; High structural similarity
  Reproduce:
    curl -X GET 'https://api.target.com/api/v1/users/123' \
      -H 'Authorization: Bearer eyJ...'
```

### JSON
```json
{
  "tool": "bola",
  "summary": {"total": 3, "high": 1, "medium": 1, "low": 1},
  "findings": [
    {
      "confidence": "HIGH",
      "method": "GET",
      "path": "/api/v1/users/{id}",
      "owner_identity": "user1",
      "tester_identity": "user2",
      "similarity": 0.95,
      "curl_command": "curl -X GET ..."
    }
  ]
}
```

## 🧪 Testing

```bash
# Unit tests
make test

# Lint
make lint

# Build verification (cross-compile)
make check-build
```

Integration tests automatically run against [OWASP crAPI](https://github.com/OWASP/crAPI) in CI.

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Priority areas:
- Additional token format support (API keys, HMAC signatures)
- GraphQL endpoint support
- OpenAPI/Swagger spec import
- Rate limit detection and backoff
- WebSocket support

## 📄 License

MIT License. See [LICENSE](LICENSE).

## 🔗 Links

- **Bug Tracker:** [GitHub Issues](https://github.com/Mutasem-mk4/bola/issues)
- **Security:** [SECURITY.md](SECURITY.md)
- **Changelog:** [CHANGELOG.md](CHANGELOG.md)

---
Developed by **Mutasem Kharma (معتصم خرما)** — [GitHub](https://github.com/Mutasem-mk4) | [Portfolio](https://mutasem-portfolio.vercel.app/) | [Twitter/X](https://twitter.com/mutasem_mk4)
