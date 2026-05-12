# Mini Shai-Hulud Scanner

Công cụ phát hiện và quét mã độc **Mini Shai-Hulud** — chiến dịch tấn công supply chain nhắm vào hệ sinh thái npm/Node.js.

---

## Tổng quan

"Mini Shai-Hulud" là chiến dịch tấn công supply chain liên tục nhắm vào hệ sinh thái npm/Node.js, thực hiện bởi nhóm tin tặc **TeamPCP** (aliases: DeadCatx3, PCPcat, ShellForce, CipherForce), có liên kết với nhóm ransomware Vect. Tính đến tháng 5/2026, đã có **4 wave** với mức độ tinh vi leo thang.

### Lịch sử các wave tấn công

| Wave | Thời gian | Mục tiêu chính | Kỹ thuật đặc trưng | Quy mô |
|---|---|---|---|---|
| **Shai-Hulud 1.0** | 09/2025 | Các package npm ngẫu nhiên qua credential phishing | `postinstall` script, sâu tự nhân bản, GitHub dead-drop repos | 500+ packages, 100+ dev accounts |
| **Shai-Hulud 2.0** | 11/2025 | `@ctrl/tinycolor`, Zapier, ENS Domains | `preinstall` script (không cần tương tác), `bun_environment.js` obfuscate, `setup_bun.js`, hủy diệt `rm -rf ~/`, GitHub Actions self-hosted runner persistence (`SHA1HULUD`) | 492 packages, 25,000+ repos, ~350 users |
| **Mini Shai-Hulud (Wave 3)** | 29/04–01/05/2026 | **npm:** `mbt`, `@cap-js/db-service`, `@cap-js/sqlite`, `@cap-js/postgres`, `intercom-client@7.0.4` (361K downloads/tuần) — **PyPI:** `lightning` (PyTorch Lightning) 2.6.2, 2.6.3 | `preinstall` hook + Bun runtime evasion, Claude Code SessionStart persistence, VS Code folderOpen tasks, Dependabot impersonation workflow injection, P2P dead-drop search (`OhNoWhatsGoingOnWithGitHub`), CIS-region exemption | 4 npm packages (SAP) + 1 (Intercom) + 2 PyPI |
| **Mini Shai-Hulud (Wave 4)** | **10–11/05/2026** | **npm:** 42 `@tanstack/*` packages (12M+ downloads/tuần), ~40 `@uipath/*`, 3 `@mistralai/*`, 5 DraftLab/DraftAuth, ~20 `@squawk/*`, 3 MesaDev, 10 TallyUI, OpenSearch, và ~10 packages khác | **Kỹ thuật đột phá:** Orphaned commit qua fork + GitHub shared storage abuse, SLSA Build Level 3 provenance forgery, OIDC token extraction từ `Runner.Worker` memory (`/proc/{pid}/mem`), `optionalDependencies` + `prepare` hook vector, Session P2P network C2 (`filev2.getsession.org`), dead-man's switch (`rm -rf ~/` nếu token bị revoke), systemd/LaunchAgent persistence | **373+ phiên bản độc, 169+ packages, 1,800+ developers** bị ảnh hưởng |

---

## Packages bị ảnh hưởng

Dưới đây là danh sách tất cả package đã biết bị ảnh hưởng qua 4 wave tấn công Shai-Hulud (09/2025 – 05/2026).

### Wave 1 & 2 — Shai-Hulud 1.0 & 2.0 (09–11/2025)

| Package | Wave | Ghi chú |
|---|---|---|
| `@ctrl/tinycolor` | Wave 2 | Hàng triệu downloads/tuần, package phổ biến nhất bị ảnh hưởng |
| Các package của Zapier | Wave 2 | Bị compromise qua credential phishing |
| Các package của ENS Domains | Wave 2 | Bị compromise qua credential phishing |
| 500+ packages khác | Wave 1 & 2 | Tự nhân bản qua npm token bị đánh cắp |

### Wave 3 — SAP CAP Ecosystem (29/04/2026)

4 package trong hệ sinh thái SAP CAP bị đầu độc ngày 29/04/2026 (09:55–12:14 UTC), tất cả được publish từ tài khoản `cloudmtabot` (đã bị GitHub suspend):

| Package | Phiên bản độc | Weekly Downloads | Phiên bản an toàn |
|---|---|---|---|
| `mbt` | 1.2.48 | ~52,000 | 1.2.47 |
| `@cap-js/db-service` | 2.10.1 | ~260,000 | 2.11.0 |
| `@cap-js/sqlite` | 2.2.2 | ~250,000 | 2.4.0 |
| `@cap-js/postgres` | 2.2.2 | ~10,000 | 2.3.0 |

### Wave 3 — Các package khác (29/04–01/05/2026)

| Package | Phiên bản độc | Weekly Downloads | Hệ sinh thái |
|---|---|---|---|
| `intercom-client` | 7.0.4 | ~361,000 | npm |
| `lightning` (PyTorch Lightning) | 2.6.2, 2.6.3 | ~350,000 | PyPI |

---

## Wave 4 — TanStack Compromise (11/05/2026) 🆕

### Tổng quan

Ngày 11/05/2026, kẻ tấn công đã chiếm quyền publish của **TanStack** (một trong những thư viện React phổ biến nhất, hơn 12 triệu weekly downloads) thông qua một kỹ thuật chưa từng thấy: **orphaned commit qua fork** kết hợp với **SLSA Build Level 3 provenance forgery**.

**CVE:** CVE-2026-45321 | **GHSA:** GHSA-g7cv-rxg3-hmpx

### Attack chain

Đây là attack vector phức tạp nhất trong lịch sử npm:

1. **Orphaned commit:** Kẻ tấn công tạo fork `TanStack/router`, push một commit "mồ côi" (không có parent history, không thuộc branch nào) chứa `@tanstack/setup` package giả với `prepare` hook
2. **GitHub shared storage abuse:** Commit mồ côi có thể truy cập qua URL `github:tanstack/router#79ac49ee...` nhờ GitHub lưu trữ chung object storage giữa repo và fork
3. **Cache poisoning:** PR `pull_request_target` được mở, chạy code của fork trong security context của base repo, đầu độc pnpm store cache
4. **OIDC token extraction:** Khi `release.yml` chạy với cache đã nhiễm độc, Python script đọc `/proc/{pid}/mem` của `Runner.Worker` process, trích xuất OIDC token (kỹ thuật giống hệt CVE-2025-30066 tj-actions/changed-files tháng 3/2025)
5. **82 phiên bản độc** được publish với **SLSA Build Level 3 provenance hợp lệ** từ chính TanStack CI/CD pipeline thật
6. **Worm lan rộng** qua OIDC token bị đánh cắp sang ~160 packages khác

### 42 @tanstack Packages Bị Ảnh Hưởng (84 Phiên Bản Độc)

Tất cả package trong hệ sinh thái TanStack Router/Start:

| Package | Phiên bản độc | Package | Phiên bản độc |
|---|---|---|---|
| `@tanstack/react-router` | 1.169.5, 1.169.8 | `@tanstack/vue-router` | 1.169.5, 1.169.8 |
| `@tanstack/solid-router` | 1.169.5, 1.169.8 | `@tanstack/router-core` | 1.169.5, 1.169.8 |
| `@tanstack/react-start` | 1.167.68, 1.167.71 | `@tanstack/solid-start` | 1.167.65, 1.167.68 |
| `@tanstack/vue-start` | 1.167.61, 1.167.64 | `@tanstack/router-plugin` | 1.167.38, 1.167.41 |
| `@tanstack/router-cli` | 1.166.46, 1.166.49 | `@tanstack/router-generator` | 1.166.45, 1.166.48 |
| `@tanstack/history` | 1.161.9, 1.161.12 | `@tanstack/router-utils` | 1.161.11, 1.161.14 |
| `@tanstack/react-router-devtools` | 1.166.16, 1.166.19 | `@tanstack/router-devtools` | 1.166.16, 1.166.19 |
| `@tanstack/router-devtools-core` | 1.167.6, 1.167.9 | `@tanstack/solid-router-devtools` | 1.166.16, 1.166.19 |
| `@tanstack/vue-router-devtools` | 1.166.16, 1.166.19 | `@tanstack/eslint-plugin-router` | 1.161.9, 1.161.12 |
| `@tanstack/eslint-plugin-start` | 0.0.4, 0.0.7 | `@tanstack/react-router-ssr-query` | 1.166.15, 1.166.18 |
| `@tanstack/solid-router-ssr-query` | 1.166.15, 1.166.18 | `@tanstack/vue-router-ssr-query` | 1.166.15, 1.166.18 |
| `@tanstack/router-ssr-query-core` | 1.168.3, 1.168.6 | `@tanstack/router-vite-plugin` | 1.166.53, 1.166.56 |
| `@tanstack/nitro-v2-vite-plugin` | 1.154.12, 1.154.15 | `@tanstack/start-client-core` | 1.168.5, 1.168.8 |
| `@tanstack/start-server-core` | 1.167.33, 1.167.36 | `@tanstack/start-plugin-core` | 1.169.23, 1.169.26 |
| `@tanstack/start-fn-stubs` | 1.161.9, 1.161.12 | `@tanstack/start-storage-context` | 1.166.38, 1.166.41 |
| `@tanstack/start-static-server-functions` | 1.166.44, 1.166.47 | `@tanstack/virtual-file-routes` | 1.161.10, 1.161.13 |
| `@tanstack/react-start-client` | 1.166.51, 1.166.54 | `@tanstack/react-start-server` | 1.166.55, 1.166.58 |
| `@tanstack/react-start-rsc` | 0.0.47, 0.0.50 | `@tanstack/solid-start-client` | 1.166.50, 1.166.53 |
| `@tanstack/solid-start-server` | 1.166.54, 1.166.57 | `@tanstack/vue-start-client` | 1.166.46, 1.166.49 |
| `@tanstack/vue-start-server` | 1.166.50, 1.166.53 | `@tanstack/arktype-adapter` | 1.166.12, 1.166.15 |
| `@tanstack/valibot-adapter` | 1.166.12, 1.166.15 | `@tanstack/zod-adapter` | 1.166.12, 1.166.15 |

**Confirmed-clean:** `@tanstack/query*`, `@tanstack/table*`, `@tanstack/form*`, `@tanstack/virtual*`, `@tanstack/store`

### Worm lan sang ~120 packages khác

| Tổ chức | Số packages | Ví dụ |
|---|---|---|
| **UiPath** | ~40+ | `@uipath/agent.sdk`, `@uipath/apollo-core`, `@uipath/cli`, `@uipath/auth`, ... |
| **Mistral AI** | 3 | `@mistralai/mistralai` (2.2.3, 2.2.4), `-azure`, `-gcp` variants |
| **DraftLab/DraftAuth** | 5 | `@draftlab/auth`, `@draftlab/db`, `@draftauth/client`, `@draftauth/core`, ... |
| **Squawk (hàng không)** | ~20 | `@squawk/airport-data`, `@squawk/weather`, `@squawk/mcp`, ... |
| **MesaDev** | 3 | `@mesadev/rest`, `@mesadev/sdk`, `@mesadev/saguaro` |
| **TallyUI** | 10 | `@tallyui/components`, `@tallyui/core`, `@tallyui/pos`, ... |
| **OpenSearch** | 1 | `@opensearch-project/opensearch` (3.6.2) |
| **Khác** | ~10 | `safe-action`, `cmux-agent-mcp`, `nextmove-mcp`, `ts-dna`, `cross-stitch`, `ml-toolkit-ts`, ... |

### Kỹ thuật mới (chỉ có trong Wave 4)

1. **SLSA Build Level 3 provenance giả mạo:** Package độc mang provenance attestation hợp lệ từ chính TanStack CI/CD
2. **Orphaned commit qua fork:** Commit mồ côi không thuộc branch nào, chỉ truy cập được qua hash, dùng GitHub shared object storage
3. **OIDC token extraction từ Runner.Worker memory:** Python đọc `/proc/{pid}/mem` — giống CVE-2025-30066
4. **Session P2P network làm C2:** `filev2.getsession.org` — không có máy chủ C2 truyền thống để block
5. **Dead-man's switch:** Token npm mới với description `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` — nếu revoke token, payload hủy `rm -rf ~/`
6. **`optionalDependencies` + `prepare` hook:** Vector mới thay cho `preinstall`, tránh bị static analysis phát hiện
7. **Double-tap publish:** Hai phiên bản độc cách nhau vài phút
8. **`exit 1` trong prepare hook:** Payload chạy xong, npm log script failure — tưởng lỗi nhưng thực chất đã nhiễm

### Payload `router_init.js`

- **Kích thước:** 2,341,681 bytes (mỗi package tăng từ ~190 KB → ~905 KB)
- **SHA-256:** `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
- **Vị trí:** Đặt ở package root, không có trong `files` field → chứng minh giả mạo ngoài build process
- **Obfuscation 3 lớp:** obfuscator.io → Fisher-Yates substitution cipher (PBKDF2-SHA256, salt `svksjrhjkcejg`, 200,000 iterations) → AES-256-GCM (11 payloads)
- **Master key:** `0c0e873033875f1bc471eda37e3b9d0f9b89bd41a4bbb4f86746caa2176c40aa`
- **Campaign string:** `EveryBoiWeBuildIsAWormyBoi`

### `optionalDependencies` Injection

Mỗi `package.json` bị nhiễm có thêm:
```json
"optionalDependencies": {
  "@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
}
```

Khi `npm install` resolve GitHub dependency, `prepare` hook chạy:
```json
{"scripts": {"prepare": "bun run tanstack_runner.js && exit 1"}}
```

### Persistence mới trong Wave 4

Ngoài Claude Code & VS Code hooks, Wave 4 thêm **dead-man's switch cấp hệ thống**:

| OS | Path |
|---|---|
| Linux | `~/.local/bin/gh-token-monitor.sh` |
| Linux | `~/.config/systemd/user/gh-token-monitor.service` |
| macOS | `~/Library/LaunchAgents/com.user.gh-token-monitor.plist` |

Các file này poll `api.github.com/user` mỗi 60 giây. Nếu token bị revoke (HTTP 40x) → thực thi `rm -rf ~/`.

**Cảnh báo:** Phải vô hiệu hóa service này TRƯỚC KHI xoay credentials.

### Indicator riêng của Wave 4

| IOC | Giá trị |
|---|---|
| **Malicious file** | `router_init.js` (2.3 MB) |
| **Malicious file** | `tanstack_runner.js` (2.3 MB) |
| **optionalDependencies hash** | `79ac49eedf774dd4b0cfa308722bc463cfe5885c` |
| **Attacker GitHub account** | `voicproducoes` (ID 269549300) |
| **Attacker GitHub account** | `zblgg` (ID 127806521) |
| **Fork name evasion** | `zblgg/configuration` (đổi tên để né fork-list search) |
| **C2 (Session P2P)** | `filev2.getsession.org` |
| **C2 (secondary)** | `api.masscan.cloud` |
| **C2 (tertiary)** | `git-tanstack.com` |
| **Payload staging** | `litter.catbox.moe/h8nc9u.js`, `litter.catbox.moe/7rrc6l.mjs` |
| **Campaign PBKDF2 salt** | `svksjrhjkcejg` |
| **Campaign string** | `EveryBoiWeBuildIsAWormyBoi` |
| **npm token description** | `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` |
| **Repo naming** | `siridar-ghola-567`, `tleilaxu-ornithopter-43` |
| **Branch pattern** | `dependabot/github_actions/format/{dune-word}` |
| **Dune wordlist** | atreides, fremen, sandworm, harkonnen, melange, ghola, kanly, sietch, sardaukar, mentat, ornithopter, heighliner, thumper, tleilaxu, stillsuit, ... (30 từ) |

`@cap-js/sqlite@2.2.2` khai báo dependency `@cap-js/db-service@^2.10.0`. Với range `^2.10.0`, một lần `npm install` sạch có thể kéo phiên bản độc `2.10.1` mà không cần package này được liệt kê trực tiếp trong `package.json`.

---

## Chi tiết kỹ thuật — Attack Chain (5 bước)

### Bước 1: Entry Point

Kẻ tấn công chiếm quyền publish và đầu độc các package tarball hợp pháp, giữ nguyên code gốc "byte-for-byte" so với bản clean trước đó. Các thay đổi gồm:

- `package.json` được thêm `preinstall` script:

```json
"scripts": {
  "preinstall": "node setup.mjs"
}
```

- Thêm 2 file mới vào tarball:
  - `setup.mjs` (~4.5 KB) — giống hệt nhau giữa 4 package
  - `execution.js` (~11.6 MB) — hash khác nhau mỗi package
- Riêng `mbt` được thêm dependencies mới: `axios`, `tar`, `unzip-stream`

### Bước 2: Trigger

npm `preinstall` lifecycle hook thực thi `node setup.mjs` **trước khi** hiển thị bất kỳ output cài đặt nào. Script này:

1. Phát hiện nền tảng/kiến trúc hệ thống (bao gồm Alpine/musl)
2. Kiểm tra binary `bun` trong PATH
3. Nếu không có, tải **Bun 1.3.13** từ `github.com/oven-sh/bun/releases`
4. Việc tải qua GitHub release infrastructure khiến traffic trông giống như developer hợp pháp với hầu hết network egress filter

### Bước 3: Execution

Bun runtime thực thi `execution.js`. File này được bảo vệ bởi 2 lớp obfuscation:

- **Lớp 1:** obfuscator.io với 48,370 string table entries, giải mã bằng bảng base64 không chuẩn
- **Lớp 2:** Mã hóa `ctf-scramble-v2` với khóa dẫn xuất từ PBKDF2

Việc chạy payload dưới Bun thay vì Node.js giúp vượt qua hầu hết endpoint security controls vốn chỉ được cấu hình để giám sát Node.

### Bước 4: CIS-region Exemption

Payload kiểm tra locale hệ thống qua Intl API và biến môi trường (`LC_ALL`, `LC_MESSAGES`, `LANGUAGE`, `LANG`). Nếu phát hiện locale tiếng Nga, nó ghi log exit message và kết thúc — không thực hiện hành vi độc hại.

### Bước 5: Credential Harvesting

Payload quét **134 đường dẫn** trên hệ thống, bao gồm tất cả danh mục credentials chính:

#### GitHub
- Personal Access Tokens (PATs)
- OAuth grants
- `gh auth token` output
- Actions secrets

#### npm
- `.npmrc` tokens
- Lọc các token có `bypass_2fa: true` và org-level write scope

#### Cloud Providers
- **AWS:** IMDS/IMDSv2 (`169.254.169.254`, `169.254.170.2`, `[fd00:ec2::254]`), ECS metadata, Secrets Manager, SSM
- **Azure:** Key Vault, token caches
- **GCP:** Secret Manager, token caches

#### Kubernetes
- `~/.kube/config`
- In-pod service account tokens
- Helm configuration

#### AI Tooling
- `~/.claude.json`
- MCP server configs
- Kiro MCP config (`~/.kiro/settings/mcp.json`)

#### SSH/TLS
- `~/.ssh/id_*`
- Host keys
- `*.pem`, `*.key`, `*.p12`, `*.pfx`
- Let's Encrypt certificates

#### Password Managers
- 1Password (`op` CLI)
- Bitwarden (`bw` CLI)
- LastPass CLI

#### Infrastructure as Code
- Terraform Cloud credentials
- `.tfvars`, `.tfstate`
- Jenkinsfile, `.gitlab-ci.yml`, `ansible.cfg`

#### Crypto Wallets
- Bitcoin, Ethereum keystores
- Solana, Cardano, Monero, Litecoin, Dogecoin, Zcash, Dash, Ripple
- Electrum, Exodus, Ledger Live, Atomic

#### Shell History
- `.bash_history`, `.zsh_history`
- `.mysql_history`, `.psql_history`, `.rediscli_history`

#### System Files
- `/etc/passwd`, `/etc/shadow`
- Auth logs

### Runner Memory Extraction (GitHub Actions)

Trên Linux GitHub Actions runners, một Python child process được spawn để:
1. Đọc `/proc/{pid}/mem` của process `Runner.Worker`
2. Quét heap của .NET process tìm pattern: `{"value":"<secret>","isSecret":true}`
3. Trích xuất toàn bộ masked secrets từ bộ nhớ runner

SHA-256 của embedded /proc/mem dumper: `29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7`

---

## Mã hóa & Exfiltration

### Quy trình mã hóa

1. Dữ liệu thu thập được serialize thành JSON
2. Gzip compress
3. Mã hóa bằng **AES-256-GCM** (key 32-byte, IV 12-byte)
4. AES key được wrap bằng **RSA-OAEP-SHA256** với RSA-4096 public key của attacker
5. RSA public key (định dạng PEM) được nhúng trong `execution.js` tại file offset 9,429,992, nén bằng gzip+base64

### Cấu trúc dead-drop

Encrypted bundle được commit lên GitHub repo công khai trên chính tài khoản nạn nhân dưới dạng JSON:

```json
{
  "envelope": "<base64 ciphertext>",
  "key": "<base64 wrapped key>"
}
```

Nếu không có RSA private key của attacker, nội dung dead-drop không thể đọc được. Điều này đồng nghĩa với việc defensive credential rotation phải được thực hiện một cách bảo thủ, xoay tất cả credentials có thể tiếp cận từ máy bị ảnh hưởng.

---

## Persistence — 3 Vector

### 1. Claude Code SessionStart Hooks

Khi GitHub token bị đánh cắp có quyền write vào repo khác, payload commit file `.claude/settings.json` chứa `SessionStart` hook — hook này tái thực thi payload mỗi khi developer mở Claude Code session.

Anthropic issue `claude-code #49778` đã báo cáo bề mặt tấn công này 12 ngày trước chiến dịch và vẫn chưa có phản hồi tại thời điểm phát hiện.

### 2. VS Code folderOpen Tasks

File `.vscode/tasks.json` được commit với cấu hình `"runOn": "folderOpen"`, thực thi khi project được mở trong VS Code.

Microsoft issue `vscode #309406` đã báo cáo 16 ngày trước đó và bị đóng với trạng thái "By Design" theo Workspace Trust model.

### 3. Dependabot-Impersonation Workflow Injection

Khi token có workflow scope, payload tạo branch typosquatted `dependabout/github_actions/format/setup-formatter` (chú ý: "dependa**b**out" thay vì "dependa**b**ot") và commit file `.github/workflows/format-check.yml` giả mạo Dependabot. Workflow này sử dụng:

```yaml
${{ toJSON(secrets) }}
```

để dump toàn bộ repository secrets vào build artifact.

### Đặc điểm chung của persistence commits

Tất cả commit dùng author signature: `claude@users.noreply.github.com`
Commit message: `"chore: update dependencies"`

---

## Self-Propagation (Cơ chế sâu)

### Nhân bản qua npm

Payload thực hiện quy trình tự nhân bản:

1. Trích xuất npm tokens khớp regex `/npm_[A-Za-z0-9]{36,}/g`
2. Validate token với npm registry, lọc `bypass_2fa: true` + org-level write scope
3. Liệt kê tất cả packages mà nạn nhân có quyền publish
4. Patch `setup.mjs` và `execution.js` vào bản copy của tarball
5. Publish qua **HTTP PUT trực tiếp** đến npm registry, bypass hoàn toàn npm CLI

### Peer-to-Peer Dead-Drop

Khi nạn nhân tại chỗ không có token khả dụng, payload thực hiện:

1. Gọi `api.github.com/search/commits?q=OhNoWhatsGoingOnWithGitHub`
2. Tìm commits từ các máy đã bị nhiễm khác
3. Giải mã base64 GitHub tokens từ commit messages
4. Thử lại các token này

Một repository exfiltration do đó có thể tương ứng với nhiều nạn nhân khác nhau.

---

## Root Cause

### @cap-js/* packages — OIDC Misconfiguration

npm Trusted Publishing configuration của `cap-js/cds-dbs` **trust toàn bộ workflow trong repo**, thay vì chỉ trust specific release workflow trên main branch. Một push đến bất kỳ feature branch nào cũng có thể nhận được OIDC publish token hợp lệ.

Đã được fix trong `cap-js/cds-dbs` PR #1592 bằng cách gate npm publish sau một GitHub Environment với manual approval.

### mbt package

Vector publish của `mbt` chưa được xác nhận công khai, ngoài việc được publish từ tài khoản `cloudmtabot`.

---

## Indicators of Compromise (IOC)

### Repository IOCs

| IOC | Giá trị |
|---|---|
| Description string | `"A Mini Shai-Hulud has Appeared"` |
| Repo naming pattern | Hai từ vũ trụ Dune + 1-3 chữ số (vd: `kanly-sietch-78`, `ghola-ornithopter-356`, `siridar-ghola-567`, `tleilaxu-ornithopter-43`) |
| P2P commit search string | `OhNoWhatsGoingOnWithGitHub` |
| Author signature | `claude@users.noreply.github.com` |
| Commit message | `"chore: update dependencies"` |
| Compromised npm account | `cloudmtabot` (suspended) |
| Attacker GitHub (Wave 4) | `voicproducoes` (ID 269549300, created 2026-03-19) |
| Attacker GitHub (Wave 4) | `zblgg` (ID 127806521), fork renamed to `zblgg/configuration` |
| Attacker email | `voicproducoes@gmail.com` |

### Payload IOCs

| IOC | Giá trị |
|---|---|
| Cipher salt (Wave 3) | `ctf-scramble-v2` |
| Cipher salt (Wave 4) | `svksjrhjkcejg` (PBKDF2, 200,000 iterations) |
| Campaign string (Wave 4) | `EveryBoiWeBuildIsAWormyBoi` |
| Daemonization env var | `__DAEMONIZED` |
| Lockfile marker | `tmp.987654321.lock` |
| Workflow injection branch | `dependabout/github_actions/format/setup-formatter` |
| Wave 4 workflow injection branch | `dependabot/github_actions/format/{dune-word}` (30 Dune từ) |
| Injected workflow file | `.github/workflows/format-check.yml` |
| Wave 4 injected workflow | `.github/workflows/codeql_analysis.yml` (2 variants) |
| Wave 4 optionalDependencies | `"@tanstack/setup": "github:tanstack/router#79ac49ee..."` |
| Wave 4 malicious orphan commit | `79ac49eedf774dd4b0cfa308722bc463cfe5885c` |
| Wave 4 npm token description | `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` |

### File Hashes (SHA-256) — Mini Shai-Hulud Wave 4 — TanStack (11/05/2026) 🆕

| File | SHA-256 |
|---|---|
| `router_init.js` (tất cả @tanstack packages) | `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c` |
| `tanstack_runner.js` (attacker commit) | `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96` |
| `@tanstack/setup` package.json (attacker commit) | `7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b` |

### File Hashes (SHA-256) — Mini Shai-Hulud Wave 3 (Tháng 4/2026)

| File | SHA-256 |
|---|---|
| `setup.mjs` (tất cả packages) | `4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34` |
| `execution.js` (mbt) | `80a3d2877813968ef847ae73b5eeeb70b9435254e74d7f07d8cf4057f0a710ac` |
| `execution.js` (@cap-js/sqlite) | `6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95` |
| Embedded /proc/mem dumper | `29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7` |

### Tarball Shasums

| Package | Shasum |
|---|---|
| `mbt@1.2.48` | `0af7415d65753f6aede8c9c0f39be478666b9c12` |
| `@cap-js/db-service@2.10.1` | `4b04304f6d51392e3f43856c94ca95800518a694` |
| `@cap-js/sqlite@2.2.2` | `7b6a28e92149637e5d7c7f4a2d3e54acd507c929` |
| `@cap-js/postgres@2.2.2` | `e80824a19f48d778a746571bb15279b5679fd61c` |

### File Hashes — Các wave trước (cũng có thể tồn tại trong source tree)

| Wave | File | SHA-256 |
|---|---|---|
| Shai-Hulud 1.0 (9/2025) | `bundle.js` | `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09` |
| Shai-Hulud 2.0 (11/2025) | `setup_bun.js` | `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a` |
| Shai-Hulud 2.0 (11/2025) | `bun_environment.js` | `f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068` |
| Shai-Hulud 2.0 (11/2025) | `bun_environment.js` (variant) | `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0` |

### Behavioral Detection Signals

- **Primary signal:** Download bất thường của `bun-v1.3.13` từ `github.com/oven-sh/bun/releases` trong quá trình `npm install`
- **Process tree:** `node` → `bun` → `python` spawning chain
- **Network:** Outbound HTTPS đến `api.github.com/user/repos` và `api.github.com/search/commits?q=OhNoWhatsGoingOnWithGitHub` trong quá trình install
- **Shai-Hulud 2.0 specific:** GitHub runner registration với flag `--name SHA1HULUD`
- **Shai-Hulud 2.0 specific:** File `bun_environment.js` >= 9 MB
- **Wave 4 specific:** `optionalDependencies` chứa `github:tanstack/router#79ac49ee...`
- **Wave 4 specific:** File `router_init.js` ở package root (không có trong `files` field)
- **Wave 4 specific:** Tarball size anomaly (từ ~190 KB → ~905 KB)
- **Wave 4 specific:** Double-tap publish (2 version cách nhau vài phút)
- **Wave 4 specific:** `prepare` hook chạy obfuscated JS qua Bun với `&& exit 1`
- **Wave 4 specific:** Python đọc `/proc/*/mem` trong CI/CD
- **Wave 4 specific:** systemd service `gh-token-monitor.service` hoặc LaunchAgent `com.user.gh-token-monitor.plist`

### C2 Endpoints

| Wave | Endpoint |
|---|---|
| Shai-Hulud 2.0 | `hxxps://webhook[.]site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7` |
| Mini Shai-Hulud Wave 4 | `filev2.getsession[.]org/file/` (Session P2P network) |
| Mini Shai-Hulud Wave 4 | `api.masscan[.]cloud/v2/upload` |
| Mini Shai-Hulud Wave 4 | `git-tanstack[.]com` |
| Mini Shai-Hulud Wave 4 | `litter.catbox[.]moe/h8nc9u.js`, `litter.catbox[.]moe/7rrc6l.mjs` |

---

## Impact

- Hơn **1,197 victim repositories** xuất hiện trên GitHub chỉ trong vài giờ đầu
- Repository nạn nhân đầu tiên xuất hiện trên tài khoản `gruposbftechrecruiter` lúc 10:01:07 UTC — **chưa đầy 6 phút** sau khi `mbt@1.2.48` được publish
- Không có CVE, GHSA, hoặc OSV record nào được gán tại thời điểm phát hiện
- Chiến dịch chia sẻ 5 TTPs với các chiến dịch TeamPCP từ tháng 3/2026: runner memory extraction, layered AES+RSA-4096 encryption, CIS-region locale exemption, AI coding agent targeting, CI/CD credential harvesting ở quy mô lớn

---

## Biện pháp phòng chống & Phát hiện

### Cho developers

1. **Khóa `preinstall` scripts:** Dùng `npm config set ignore-scripts true` hoặc `npm install --ignore-scripts`
2. **Pin dependencies:** Luôn lock version cụ thể, tránh dùng range `^` hoặc `~` mở
3. **Enforce MFA:** Bắt buộc 2FA cho tất cả tài khoản npm và GitHub
4. **Audit định kỳ:** Chạy `npm audit`, kiểm tra `package-lock.json`/`yarn.lock`
5. **Kiểm tra GitHub account:** Tìm repo công khai lạ, suspicious commits, workflow modifications bất thường
6. **Review OIDC publishing:** Chỉ trust specific workflow + branch, không trust toàn bộ repo. Sử dụng GitHub Environment với manual approval.

### Cho security teams

1. **Giám sát network:** Phát hiện download Bun runtime bất thường trong CI/CD pipeline
2. **Process monitoring:** Cảnh báo khi thấy process chain `node` → `bun` → `python`
3. **DNS/HTTP monitoring:** Theo dõi requests đến `api.github.com/search/commits?q=OhNoWhatsGoingOnWithGitHub`
4. **File integrity monitoring:** Phát hiện file `setup.mjs`, `execution.js`, `setup_bun.js`, `bun_environment.js` trong source tree
5. **Hash matching:** So khớp file hashes với known-malicious IOCs
6. **Preinstall script audit:** Kiểm tra tất cả `preinstall` scripts trong `package.json` của dependencies

### Detection rules (Sigma/YARA)

Các rule phát hiện nên tập trung vào:
- File hash matching với các IOC trong bảng trên
- String matching: `ctf-scramble-v2`, `OhNoWhatsGoingOnWithGitHub`, `A Mini Shai-Hulud has Appeared`, `tmp.987654321.lock`
- Process creation: `bun` spawned từ `npm` hoặc `node` context
- Network: HTTP requests chứa `OhNoWhatsGoingOnWithGitHub`
- File creation: `.claude/settings.json` với `SessionStart` hook, `.vscode/tasks.json` với `folderOpen` trigger

---

## Nguồn tham khảo

- [Phoenix Security — Mini Shai-Hulud: SAP CAP npm Worm with Bun + Claude Code Persistence](https://phoenix.security/mini-shai-hulud-sap-cap-mbt-npm-supply-chain-bun-credential-stealer/)
- [Unit 42 (Palo Alto Networks) — "Shai-Hulud" Worm Compromises npm Ecosystem](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [CISA — Widespread Supply Chain Compromise Impacting npm Ecosystem](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [StepSecurity — TeamPCP's Mini Shai-Hulud Is Back](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)
- [JFrog — Shai-Hulud npm Supply Chain Attack](https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/)
- [Wiz — Shai-Hulud npm Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)
- [Checkmarx — NPM Hit By Shai-Hulud](https://checkmarx.com/zero-post/npm-hit-by-shai-hulud-the-self-replicating-supply-chain-attack/)
- [BleepingComputer — Shai-Hulud malware infects 500 npm packages](https://www.bleepingcomputer.com/news/security/shai-hulud-malware-infects-500-npm-packages-leaks-secrets-on-github/)
- [CSA Research — Mini Shai-Hulud: Multi-Ecosystem Developer Supply Chain Attack](https://labs.cloudsecurityalliance.org/research/csa-research-note-mini-shai-hulud-multi-ecosystem-supply-cha/)
- [The Hacker News — SAP-Related npm Packages Compromised](https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html)
