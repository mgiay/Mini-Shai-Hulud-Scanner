# Mini Shai-Hulud Scanner

Công cụ phát hiện và quét mã độc **Mini Shai-Hulud** — chiến dịch tấn công supply chain nhắm vào hệ sinh thái npm/Node.js.

---

## Tổng quan

"Mini Shai-Hulud" là wave thứ 3 trong chuỗi tấn công supply chain Shai-Hulud, được thực hiện bởi nhóm tin tặc **TeamPCP**, phát hiện vào **29/04/2026**. Chiến dịch này là cross-ecosystem (npm + PyPI), sử dụng **Bun runtime** để né tránh các công cụ endpoint security vốn chỉ giám sát Node.js.

### Lịch sử các wave tấn công

| Wave | Thời gian | Đặc điểm chính |
|---|---|---|
| **Shai-Hulud 1.0** | Tháng 9/2025 | Sâu tự nhân bản qua npm, dùng `postinstall` script, hơn 500 packages bị nhiễm |
| **Shai-Hulud 2.0** | Tháng 11/2025 | Chuyển sang `preinstall` script (không cần tương tác người dùng), thêm cơ chế hủy diệt home directory, hơn 25,000 repos bị ảnh hưởng, ~350 người dùng bị compromise |
| **Mini Shai-Hulud** | Tháng 4/2026 | Đa hệ sinh thái (npm + PyPI), dùng Bun runtime thay Node.js để né detection, nhắm vào SAP CAP packages và PyTorch Lightning |

---

## Packages bị ảnh hưởng

Ngày 29/04/2026 (09:55–12:14 UTC), 4 package trong hệ sinh thái SAP CAP bị đầu độc, tất cả được publish từ tài khoản `cloudmtabot` (đã bị GitHub suspend):

| Package | Phiên bản độc | Weekly Downloads | Phiên bản an toàn |
|---|---|---|---|
| `mbt` | 1.2.48 | ~52,000 | 1.2.47 |
| `@cap-js/db-service` | 2.10.1 | ~260,000 | 2.11.0 |
| `@cap-js/sqlite` | 2.2.2 | ~250,000 | 2.4.0 |
| `@cap-js/postgres` | 2.2.2 | ~10,000 | 2.3.0 |

### Rủi ro transitive

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
| Repo naming pattern | Hai từ vũ trụ Dune + 1-3 chữ số (vd: `kanly-sietch-78`, `ghola-ornithopter-356`) |
| P2P commit search string | `OhNoWhatsGoingOnWithGitHub` |
| Author signature | `claude@users.noreply.github.com` |
| Commit message | `"chore: update dependencies"` |
| Compromised npm account | `cloudmtabot` (suspended) |

### Payload IOCs

| IOC | Giá trị |
|---|---|
| Cipher salt | `ctf-scramble-v2` |
| Daemonization env var | `__DAEMONIZED` |
| Lockfile marker | `tmp.987654321.lock` |
| Workflow injection branch | `dependabout/github_actions/format/setup-formatter` |
| Injected workflow file | `.github/workflows/format-check.yml` |

### File Hashes (SHA-256) — Mini Shai-Hulud (Wave 3)

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

### C2 Endpoint (Shai-Hulud 2.0)

- `hxxps://webhook[.]site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`

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
