# Mini Shai-Hulud Scanner — Hướng Dẫn Sử Dụng Chi Tiết

## Mục lục

1. [Tổng quan](#tổng-quan)
2. [Cài đặt & Yêu cầu](#cài-đặt--yêu-cầu)
3. [Cách sử dụng cơ bản](#cách-sử-dụng-cơ-bản)
4. [11 Module quét — Chi tiết](#11-module-quét--chi-tiết)
5. [Các chế độ & Tùy chọn](#các-chế-đ--tùy-chọn)
6. [Kịch bản sử dụng thực tế](#kịch-bản-sử-dụng-thực-tế)
7. [Đọc kết quả đầu ra](#đọc-kết-quả-đầu-ra)
8. [Tích hợp CI/CD](#tích-hợp-cicd)
9. [Xử lý khi phát hiện threat](#xử-lý-khi-phát-hiện-threat)
10. [Exit codes](#exit-codes)
11. [FAQ](#faq)

---

## Tổng quan

**Mini-Shai-Hulud-Scanner.sh** v1.1.0 là công cụ dòng lệnh dành cho Linux, quét và phát hiện dấu vết của mã độc Mini Shai-Hulud / Shai-Hulud — chuỗi tấn công supply chain do nhóm **TeamPCP** thực hiện, nhắm vào hệ sinh thái npm/Node.js (và PyPI) từ tháng 9/2025 đến nay.

### Phạm vi phát hiện

Script bao phủ **toàn bộ 4 wave tấn công** đã biết:

| Wave | Thời gian | Phạm vi phát hiện |
|---|---|---|
| Shai-Hulud 1.0 | 09/2025 | `bundle.js`, `postinstall` scripts, C2 endpoints |
| Shai-Hulud 2.0 | 11/2025 | `setup_bun.js`, `bun_environment.js`, SHA1HULUD runner, `preinstall` hooks, C2 webhook |
| Mini Shai-Hulud (Wave 3) | 04/2026 | SAP CAP (`mbt`, `@cap-js/*`), `intercom-client`, `setup.mjs`, `execution.js`, Claude Code hooks, VS Code tasks, Dependabot impersonation |
| Mini Shai-Hulud (Wave 4) | 05/2026 | 42 `@tanstack/*` packages, 40+ `@uipath/*`, `@mistralai/*`, `router_init.js`, `tanstack_runner.js`, `optionalDependencies` vector, `prepare` hook, dead-man's switch (systemd/LaunchAgent), Session P2P C2, SLSA provenance forgery detection |

### Chỉ số IOC được bao phủ

| Loại IOC | Số lượng |
|---|---|
| Known-malicious SHA-256 hashes | **16** (cả 4 wave) |
| Known-malicious tarball shasums | **4** (Wave 3) |
| IOC strings | **22** (cả 4 wave) |
| Malicious filenames | **7** (cả 4 wave) |
| Persistence paths | **13** (cả 4 wave) |
| Compromised version checks | **20+** packages |

Script thực hiện **11 module quét độc lập**, bao phủ toàn bộ attack chain: file payload, IOC strings, persistence mechanisms, process đang chạy, GitHub dead-drop repos, npm token threats, và dead-man's switch services.

---

## Cài đặt & Yêu cầu

### Yêu cầu hệ thống

| Công cụ | Bắt buộc | Dùng cho module |
|---|---|---|
| `bash` >= 4.0 | Có | Toàn bộ script |
| `sha256sum` | Có | Quét hash file |
| `find` | Có | Tìm kiếm file |
| `grep` | Có | Quét IOC strings |
| `jq` | Có | Phân tích JSON (package.json, lock files) |
| `stat` | Có | Kiểm tra kích thước file |
| `gh` CLI | Không | Quét GitHub dead-drop repos (chỉ với `-g`) |
| `pgrep` | Không | Quét process (chỉ với `-p`, tự bỏ qua nếu thiếu) |

### Cài đặt

```bash
# Tải script
wget https://your-server/Mini-Shai-Hulud-Scanner.sh
# hoặc
curl -O https://your-server/Mini-Shai-Hulud-Scanner.sh

# Cấp quyền thực thi
chmod +x Mini-Shai-Hulud-Scanner.sh

# Kiểm tra
./Mini-Shai-Hulud-Scanner.sh --help
```

### Cài đặt dependencies (Ubuntu/Debian)

```bash
sudo apt update && sudo apt install -y jq coreutils findutils grep
```

### Cài đặt dependencies (RHEL/CentOS/Fedora)

```bash
sudo dnf install -y jq coreutils findutils grep
```

---

## Cách sử dụng cơ bản

### Cú pháp

```
./Mini-Shai-Hulud-Scanner.sh [OPTIONS] <SCAN_DIRECTORY>
```

**SCAN_DIRECTORY là bắt buộc** — script sẽ không tự động quét thư mục hiện tại. Để quét thư mục hiện tại, dùng `.`:

```bash
./Mini-Shai-Hulud-Scanner.sh .
```

### Các lệnh cơ bản

```bash
# Quét project hiện tại
./Mini-Shai-Hulud-Scanner.sh /home/user/my-project

# Quét toàn bộ hệ thống (cần root)
sudo ./Mini-Shai-Hulud-Scanner.sh /

# Quick scan + verbose
./Mini-Shai-Hulud-Scanner.sh -q -v /opt/app

# Quét + kiểm tra process + xuất report
./Mini-Shai-Hulud-Scanner.sh -p -o scan-report.txt /var/www
```

---

## 11 Module quét — Chi tiết

### Module 1: Malicious File Hash Scan

**Mục đích:** Phát hiện file payload đã biết qua SHA-256 hash.

**Cách hoạt động:**
- Duyệt tất cả file trong thư mục quét
- Tính SHA-256 hash cho từng file
- So khớp với cơ sở dữ liệu 13 known-malicious hashes từ cả 3 wave tấn công
- Bao gồm hash cho: `setup.mjs`, `execution.js`, `setup_bun.js`, `bun_environment.js`, `bundle.js` và các variant

**Kết quả đầu ra khi phát hiện:**
```
[THREAT] KNOWN MALICIOUS HASH [4066781fa...]: /home/user/project/node_modules/.cache/setup.mjs (4608 bytes)
```

**Kết quả đầu ra khi sạch (verbose mode):**
```
[INFO]  Scanned 15420 files for known hashes
```

**Lưu ý:** Ở chế độ quick scan (`-q`), module này chỉ quét file `*.js`, `*.mjs`, `*.cjs`, `*.tgz`.

---

### Module 2: IOC String Scan

**Mục đích:** Tìm kiếm chuỗi indicator of compromise trong nội dung file.

**Các chuỗi được quét:**

| IOC String | Ý nghĩa |
|---|---|
| `ctf-scramble-v2` | Cipher marker của payload Mini Shai-Hulud |
| `OhNoWhatsGoingOnWithGitHub` | P2P dead-drop search string |
| `A Mini Shai-Hulud has Appeared` | Description của dead-drop repo |
| `Sha1-Hulud: The Second Coming` | Description của Shai-Hulud 2.0 repo |
| `__DAEMONIZED` | Biến môi trường daemon hóa payload |
| `tmp.987654321.lock` | Lockfile marker của payload |
| `dependabout/github_actions/format/setup-formatter` | Branch typosquat Dependabot (Wave 3) |
| `dependabot/github_actions/format/` | Branch pattern Wave 4 (30 Dune từ) |
| `cloudmtabot` | Tài khoản npm bị compromise (Wave 3) |
| `79ac49eedf774dd4b0cfa308722bc463cfe5885c` | Orphan commit hash (Wave 4 TanStack) |
| `svksjrhjkcejg` | PBKDF2 salt Wave 4 payload |
| `EveryBoiWeBuildIsAWormyBoi` | Campaign internal name Wave 4 |
| `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` | npm token threat description Wave 4 |
| `filev2.getsession.org` | Session P2P C2 (Wave 4) |
| `api.masscan.cloud` | Secondary C2 (Wave 4) |
| `git-tanstack.com` | Attacker-controlled domain (Wave 4) |
| `litter.catbox.moe` | Payload staging (Wave 4) |
| `voicproducoes` | Attacker GitHub account (Wave 4) |
| `gh-token-monitor` | Dead-man's switch service (Wave 4) |

**Phạm vi tìm kiếm:** File `*.js`, `*.mjs`, `*.json`, `*.ts`, `*.yml`, `*.yaml`, `*.sh`, `*.py`, `*.txt`, `*.md`.

**Kết quả đầu ra khi phát hiện:**
```
[THREAT] IOC string 'ctf-scramble-v2' found in: /opt/app/node_modules/evil-pkg/payload.js (line 42)
```

---

### Module 3: Malicious Filename Scan

**Mục đích:** Phát hiện file có tên khớp với known-malicious filenames.

**Tên file bị flag:**

| Filename | Wave |
|---|---|
| `setup.mjs` | Mini Shai-Hulud (Wave 3) |
| `execution.js` | Mini Shai-Hulud (Wave 3) |
| `setup_bun.js` | Shai-Hulud 2.0 (Wave 2) |
| `bun_environment.js` | Shai-Hulud 2.0 (Wave 2) |
| `bundle.js` | Shai-Hulud 1.0 (Wave 1) |
| `router_init.js` | Mini Shai-Hulud Wave 4 — TanStack (2.3 MB) |
| `tanstack_runner.js` | Mini Shai-Hulud Wave 4 — TanStack (2.3 MB) |

**Kết quả đầu ra khi phát hiện:**
```
[THREAT] Malicious filename: /tmp/execution.js (size: 12156928 bytes, hash: 80a3d28778...)
```

Module này cũng hiển thị kích thước và SHA-256 hash của file để bạn có thể đối chiếu ngay với cơ sở dữ liệu IOC.

---

### Module 4: Large JavaScript Files (>9MB)

**Mục đích:** Phát hiện file JS bất thường về kích thước — dấu hiệu của payload bị obfuscate.

**Cách hoạt động:**
- Tìm tất cả file `*.js`, `*.mjs`, `*.cjs` > 9MB
- Bỏ qua thư mục `node_modules` (có thể chứa file lớn hợp pháp)
- Với mỗi file tìm thấy, kiểm tra thêm:
  - Có chứa `ctf-scramble-v2` không?
  - Có tham chiếu đến `oven-sh/bun/releases` không?

**Kết quả đầu ra khi phát hiện:**
```
[THREAT] Suspicious large JS file (>9MB): /home/user/execution.js (size: 12156928 bytes, hash: 80a3d28778...)
[THREAT]   -> FILE CONTAINS ctf-scramble-v2 CIPHER MARKER
[THREAT]   -> FILE REFERENCES BUN DOWNLOAD URL
```

**Ngữ cảnh:** Payload `execution.js` của Mini Shai-Hulud khoảng 11.6 MB, `bun_environment.js` của Shai-Hulud 2.0 >= 9 MB.

---

### Module 5: Suspicious Preinstall/Prepare Script Audit

**Mục đích:** Phát hiện `preinstall` và `prepare` scripts độc hại trong `package.json` — vector lây nhiễm chính của tất cả các wave. Wave 4 dùng `prepare` hook trong `optionalDependencies` thay vì `preinstall`.

**Cách hoạt động:**
1. Tìm tất cả file `package.json` trong thư mục quét
2. Trích xuất `scripts.preinstall` và `scripts.prepare` nếu có
3. Cảnh báo các script tham chiếu đến file độc (`setup.mjs`, `execution.js`, `tanstack_runner.js`) hoặc download Bun runtime
4. **Wave 4 specific:** Phát hiện `optionalDependencies` chứa `github:tanstack/router#79ac49ee...`
5. **Wave 4 specific:** Phát hiện `prepare` hook với `bun run tanstack_runner.js && exit 1`
6. Đối chiếu `name` + `version` với danh sách package đã biết là độc (Wave 3 + Wave 4)

**Danh sách version bị flag:**

| Package | Version độc | Wave |
|---|---|---|
| `mbt` | 1.2.48 | Wave 3 |
| `@cap-js/db-service` | 2.10.1 | Wave 3 |
| `@cap-js/sqlite` | 2.2.2 | Wave 3 |
| `@cap-js/postgres` | 2.2.2 | Wave 3 |
| `@tanstack/react-router` | 1.169.5, 1.169.8 | Wave 4 |
| `@tanstack/vue-router` | 1.169.5, 1.169.8 | Wave 4 |
| `@tanstack/solid-router` | 1.169.5, 1.169.8 | Wave 4 |
| `@tanstack/router-core` | 1.169.5, 1.169.8 | Wave 4 |
| `@tanstack/react-start` | 1.167.68, 1.167.71 | Wave 4 |
| `@tanstack/router-plugin` | 1.167.38, 1.167.41 | Wave 4 |
| `@tanstack/router-cli` | 1.166.46, 1.166.49 | Wave 4 |
| `@tanstack/history` | 1.161.9, 1.161.12 | Wave 4 |
| `@mistralai/mistralai` | 2.2.3, 2.2.4 | Wave 4 |
| `@mistralai/mistralai-azure` | 1.7.2, 1.7.3 | Wave 4 |
| `@mistralai/mistralai-gcp` | 1.7.2, 1.7.3 | Wave 4 |
| `@opensearch-project/opensearch` | 3.6.2 | Wave 4 |

**Kết quả đầu ra khi phát hiện:**
```
[WARN]  Package [my-package@1.0.0] has preinstall script: node setup.mjs
[THREAT]   -> DANGEROUS: preinstall references known malicious file or downloads Bun
[THREAT] COMPROMISED VERSION: @cap-js/sqlite@2.2.2 in /project/package.json

# Wave 4 specific outputs:
[THREAT] Wave 4 TanStack prepare hook: [@tanstack/setup@0.0.1] bun run tanstack_runner.js && exit 1
[WARN]  Suspicious prepare hook with exit 1: [evil-pkg@1.0.0] node payload.js && exit 1
[THREAT] Wave 4 TanStack malicious optionalDependency in [@tanstack/react-router]: @tanstack/setup:github:tanstack/router#79ac49ee...
[THREAT] COMPROMISED VERSION (Wave 4 TanStack): @tanstack/react-router@1.169.5 in /project/package.json
[THREAT] COMPROMISED VERSION (Wave 4 Mistral): @mistralai/mistralai@2.2.3 in /project/package.json
```

---

### Module 6: Persistence Mechanism Artifacts

**Mục đích:** Phát hiện các cơ chế persistence mà payload cài vào project.

**Các artifact được kiểm tra:**

| Đường dẫn | Cơ chế persistence | Dấu hiệu cụ thể |
|---|---|---|
| `.claude/settings.json` | Claude Code SessionStart hook | Key `hooks.SessionStart` tồn tại |
| `.vscode/tasks.json` | VS Code folderOpen task | `"runOn": "folderOpen"` |
| `.github/workflows/format-check.yml` | Dependabot impersonation | Chứa `toJSON(secrets)` |
| `.github/workflows/discussion.yaml` | Self-hosted runner registration | File tồn tại |
| `.github/workflows/shai-hulud-workflow.yml` | Workflow độc của Shai-Hulud 1.0/2.0 | File tồn tại |
| `.github/workflows/codeql_analysis.yml` | Wave 4 injected workflow — dump `toJSON(secrets)` | Chứa `toJSON(secrets)` |
| `.claude/router_runtime.js` | Wave 4 Claude Code payload self-copy | File tồn tại |
| `.claude/setup.mjs` | Wave 4 ESM loader shim | File tồn tại |
| `.vscode/setup.mjs` | Wave 4 VS Code payload shim | File tồn tại |
| `.local/bin/gh-token-monitor.sh` | Wave 4 dead-man's switch script (Linux) | File tồn tại |
| `.config/systemd/user/gh-token-monitor.service` | Wave 4 dead-man's switch systemd service | File tồn tại |
| `Library/LaunchAgents/com.user.gh-token-monitor.plist` | Wave 4 dead-man's switch LaunchAgent (macOS) | File tồn tại |

**Phạm vi quét:**
- `$HOME` của user hiện tại
- Thư mục `$SCAN_ROOT`
- Nếu chạy với `sudo` (root): quét thêm tất cả thư mục `/home/*`

**Kết quả đầu ra khi phát hiện:**
```
[THREAT] Claude Code SessionStart hook: /home/user/project/.claude/settings.json
[THREAT] VS Code folderOpen task: /home/user/project/.vscode/tasks.json -> node /tmp/payload.js
[THREAT] Dependabot impersonation workflow (secrets dump): /home/user/project/.github/workflows/format-check.yml
[THREAT] Wave 4 injected CodeQL workflow (secrets dump): /home/user/project/.github/workflows/codeql_analysis.yml
[THREAT] Wave 4 Claude Code / VS Code payload: /home/user/project/.claude/router_runtime.js
[THREAT] Wave 4 dead-man's switch service: /home/user/.config/systemd/user/gh-token-monitor.service (DISABLE BEFORE REVOKING TOKENS!)
```

---

### Module 7: Running Process Scan

**Mục đích:** Phát hiện payload đang chạy trong memory. **Chỉ hoạt động khi có flag `-p`.**

**Các chỉ báo được kiểm tra:**

| Chỉ báo | Phương pháp |
|---|---|
| Process chain `node → bun → python` | `pgrep -f bun` + kiểm tra parent process |
| Biến môi trường `__DAEMONIZED` | Kiểm tra env var của shell hiện tại |
| Lockfile `tmp.987654321.lock` | Kiểm tra `/tmp/tmp.987654321.lock` |
| GitHub runner `SHA1HULUD` | `pgrep -f SHA1HULUD` |

**Kết quả đầu ra khi phát hiện:**
```
[THREAT] Bun process spawned from Node.js context: PID=12345, Parent=12300 (npm)
[THREAT] Environment variable __DAEMONIZED is set!
[THREAT] Malware lockfile exists: /tmp/tmp.987654321.lock
[THREAT] GitHub Actions runner registered with name SHA1HULUD!
```

---

### Module 8: GitHub Account Dead-Drop Check

**Mục đích:** Phát hiện dead-drop repos trên GitHub account của người dùng. **Chỉ hoạt động khi có flag `-g`** và đã cài `gh` CLI.

**Cách hoạt động:**
1. Kiểm tra xác thực GitHub (`gh auth status`)
2. Liệt kê tất cả public repos (tối đa 200)
3. Tìm repo có description khớp pattern: `Mini Shai-Hulud`, `Shai-Hulud`, `Sha1-Hulud`
4. Tìm kiếm commits từ author `claude@users.noreply.github.com` từ tháng 3/2026

**Kết quả đầu ra khi phát hiện:**
```
[THREAT] Suspicious GitHub repo (dead-drop indicator): kanly-sietch-78: A Mini Shai-Hulud has Appeared
[THREAT] Found 3 commits from suspicious author (claude@users.noreply.github.com) since March 2026!
```

---

### Module 9: Environment & System Indicators

**Mục đích:** Phát hiện dấu hiệu xâm nhập qua biến môi trường, binary, và npm cache.

**Các chỉ báo:**

| Chỉ báo | Phương pháp |
|---|---|
| Biến môi trường độc | Kiểm tra `__DAEMONIZED` |
| Token lộ trong env | Kiểm tra `NPM_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN` |
| Bun binary đáng ngờ | Kiểm tra Bun không được cài qua `dpkg`/`rpm` |
| Tarball độc trong npm cache | Tìm hash của tarball đã biết trong `~/.npm/_cacache` |
| **Wave 4:** npm token đe dọa | `npm token list` tìm token có description `IfYouRevokeThisToken...` |
| **Wave 4:** Dead-man's switch systemd | `~/.config/systemd/user/gh-token-monitor.service` |
| **Wave 4:** Dead-man's switch LaunchAgent | `~/Library/LaunchAgents/com.user.gh-token-monitor.plist` |
| **Wave 4:** Dead-man's switch script | `~/.local/bin/gh-token-monitor.sh` |

**Kết quả đầu ra khi phát hiện:**
```
[THREAT] Malware daemon env var set: __DAEMONIZED
[WARN]  Sensitive token in environment: GH_TOKEN (consider unsetting)
[WARN]  Bun runtime found at: /usr/local/bin/bun
[WARN]    -> Bun was NOT installed via system package manager
[THREAT] Known malicious tarball found in npm cache: 0af7415d6575...
[THREAT] Wave 4 dead-man's switch npm token detected! DO NOT REVOKE BEFORE ISOLATING MACHINE.
[THREAT] Wave 4 dead-man's switch systemd service exists! Disable before revoking tokens: systemctl --user stop gh-token-monitor
[THREAT] Wave 4 dead-man's switch LaunchAgent exists! Unload before revoking tokens: launchctl unload ...
```

---

### Module 10: Known Compromised Dependency Versions

**Mục đích:** Đối chiếu lock files với danh sách package/version đã biết là độc.

**File được kiểm tra:**
- `package-lock.json` (npm)
- `yarn.lock` (Yarn)
- `pnpm-lock.yaml` (pnpm)

**Kết quả đầu ra khi phát hiện:**
```
[THREAT] Compromised package in lockfile: mbt@1.2.48 in /project/package-lock.json (Mini Shai-Hulud Wave 3, April 2026)
[WARN]  Potentially compromised package: @ctrl/tinycolor in /project/yarn.lock (Shai-Hulud 2.0, November 2025)
[WARN]  Potentially compromised package: @tanstack/react-router in /project/package-lock.json (Mini Shai-Hulud Wave 4, May 2026 - check version)
[WARN]  Potentially compromised package: @mistralai/mistralai in /project/yarn.lock (Mini Shai-Hulud Wave 4, May 2026 - check version)
```

---

### Module 11: Credential File Exposure Check

**Mục đích:** Phát hiện file credentials có permissions yếu hoặc shell history bất thường — dấu hiệu đã bị exfiltration.

**Các kiểm tra:**

| Loại | Mô tả |
|---|---|
| SSH keys permissions | `~/.ssh/id_*` phải là `600` hoặc `400` |
| Certificate files | `*.pem`, `*.p12`, `*.pfx` phải có permissions an toàn |
| Shell history size | `.bash_history`, `.zsh_history`, `.mysql_history` > 10MB là đáng ngờ |

**Kết quả đầu ra khi phát hiện:**
```
[WARN]  Weak permissions (644) on credential file: /home/user/.ssh/id_rsa
[WARN]  Unusually large history file: /home/user/.bash_history (15728640 bytes)
```

---

## Các chế độ & Tùy chọn

### Đầy đủ các flags

| Flag | Ý nghĩa | Module ảnh hưởng |
|---|---|---|
| `-q` | Quick mode | Module 1 chỉ quét file JS, bỏ qua quét toàn bộ |
| `-p` | Process check | Bật Module 7 |
| `-g` | GitHub check | Bật Module 8 (cần `gh` CLI) |
| `-o <file>` | Xuất report | Ghi kết quả vào file định dạng pipe-delimited |
| `-v` | Verbose | In chi tiết từng bước, kể cả "not found" |
| `-h`, `--help` | Trợ giúp | Hiển thị hướng dẫn |

### So sánh chế độ

| Tiêu chí | Full Scan | Quick Scan (`-q`) |
|---|---|---|
| Thời gian | Vài phút đến hàng giờ | Vài giây đến vài phút |
| File quét | Tất cả | Chỉ `*.js`, `*.mjs`, `*.cjs`, `*.tgz` |
| Độ chính xác | Cao nhất | Có thể bỏ sót payload đổi tên |
| Phù hợp cho | Audit định kỳ, điều tra sự cố | CI/CD pipeline, quét nhanh |

---

## Kịch bản sử dụng thực tế

### 1. Quét server production

```bash
# Đăng nhập server, chạy với sudo để quét toàn bộ
sudo ./Mini-Shai-Hulud-Scanner.sh -p -o /var/log/shai-hulud-scan.txt /
```

**Giải thích:**
- `sudo` để có quyền đọc tất cả file hệ thống và `/home/*`
- `-p` để kiểm tra process nghi ngờ đang chạy
- `-o` lưu report để audit trail
- `/` quét toàn bộ filesystem

### 2. Quét CI/CD runner

```bash
# Chạy trong GitHub Actions / GitLab CI
./Mini-Shai-Hulud-Scanner.sh -q -p -o ci-scan-report.txt "$GITHUB_WORKSPACE"

# Kiểm tra exit code
if [ $? -ne 0 ]; then
    echo "THREAT DETECTED! Blocking pipeline."
    exit 1
fi
```

### 3. Kiểm tra máy developer nghi ngờ

```bash
# Quét đầy đủ: file + process + GitHub account
./Mini-Shai-Hulud-Scanner.sh -p -g -v -o forensic-report.txt /home/developer
```

### 4. Audit định kỳ hàng tuần (cron)

```bash
# Thêm vào crontab (chạy 3h sáng thứ 2)
# 0 3 * * 1 /opt/scanner/Mini-Shai-Hulud-Scanner.sh -q -o /var/log/shai-hulud-$(date +\%Y\%m\%d).txt /opt/app
```

### 5. Kiểm tra trước khi deploy

```bash
# Tích hợp vào pipeline — chặn deploy nếu phát hiện threat
./Mini-Shai-Hulud-Scanner.sh -q /opt/staging/app || {
    echo "Security scan failed! Aborting deploy."
    exit 1
}
```

### 6. Điều tra sự cố (Incident Response)

```bash
# Thu thập đầy đủ bằng chứng
mkdir -p /tmp/ir-scan
./Mini-Shai-Hulud-Scanner.sh -p -g -v -o /tmp/ir-scan/scan-report.txt / 2>&1 | tee /tmp/ir-scan/scan-output.log
```

---

## Đọc kết quả đầu ra

### Giải thích các mức độ cảnh báo

| Mức độ | Màu | Ý nghĩa |
|---|---|---|
| `[THREAT]` | Đỏ + Đậm | **Xác nhận dương tính** — phát hiện IOC khớp chính xác, cần hành động ngay |
| `[WARN]` | Vàng | **Nghi ngờ** — dấu hiệu bất thường nhưng chưa chắc là mã độc, cần điều tra thêm |
| `[INFO]` | Cyan | Thông tin trạng thái — tiến trình quét, số file đã kiểm tra |
| `[OK]` | Xanh | Xác nhận sạch — hạng mục quét không phát hiện gì |
| `[ERROR]` | Đỏ | Lỗi kỹ thuật — thiếu dependency, không đọc được file |

### Định dạng report file

Khi dùng `-o <file>`, report được ghi với định dạng pipe-delimited:

```
# Mini Shai-Hulud Scan Report - 2026-05-12 14:30:00 UTC
# Scan root: /opt/app
#
HASH_MATCH|4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34|/opt/app/cache/setup.mjs|4608
IOC_STRING|ctf-scramble-v2|/opt/app/node_modules/evil/payload.js|42
PERSISTENCE_CLAUDE_HOOK|/home/user/.claude/settings.json|node /tmp/payload.js
LOCKFILE_COMPROMISED|mbt@1.2.48|/opt/app/package-lock.json
```

Các trường: `LOẠI_PHÁT_HIỆN|chi_tiết_1|chi_tiết_2|...`

Bạn có thể dễ dàng parse report này bằng script:

```bash
# Đếm số loại threat
cut -d'|' -f1 scan-report.txt | grep -v '^#' | sort | uniq -c | sort -rn

# Trích xuất tất cả file path bị ảnh hưởng
grep -E '^(HASH_MATCH|IOC_STRING|MALICIOUS_FILENAME|LARGE_JS)' scan-report.txt | cut -d'|' -f3 | sort -u

# Lọc riêng threat (không phải warn)
grep -v '^#' scan-report.txt | grep -v 'WARN'
```

---

## Tích hợp CI/CD

### GitHub Actions

```yaml
name: Mini Shai-Hulud Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 3 * * 1'  # Hàng tuần lúc 3h sáng thứ 2

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: sudo apt-get update && sudo apt-get install -y jq

      - name: Run Mini Shai-Hulud Scanner
        run: |
          chmod +x ./Mini-Shai-Hulud-Scanner.sh
          ./Mini-Shai-Hulud-Scanner.sh -q -o scan-report.txt .

      - name: Upload scan report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: shai-hulud-scan-report
          path: scan-report.txt

      - name: Check for threats
        run: |
          if grep -q '^HASH_MATCH\|^IOC_STRING\|^MALICIOUS_FILENAME\|^PERSISTENCE\|^THREAT' scan-report.txt; then
            echo "::error::THREATS DETECTED - Review scan report!"
            cat scan-report.txt
            exit 1
          fi
```

### GitLab CI

```yaml
mini-shai-hulud-scan:
  stage: security
  image: ubuntu:latest
  before_script:
    - apt-get update && apt-get install -y jq coreutils
  script:
    - chmod +x ./Mini-Shai-Hulud-Scanner.sh
    - ./Mini-Shai-Hulud-Scanner.sh -q -o scan-report.txt "$CI_PROJECT_DIR"
  after_script:
    - |
      if grep -qE '^(HASH_MATCH|IOC_STRING|MALICIOUS_FILENAME|PERSISTENCE)' scan-report.txt 2>/dev/null; then
        echo "THREATS DETECTED!"
        cat scan-report.txt
        exit 1
      fi
  artifacts:
    when: always
    paths:
      - scan-report.txt
    expire_in: 30 days
```

### Jenkins Pipeline

```groovy
stage('Security Scan') {
    steps {
        sh '''
            chmod +x ./Mini-Shai-Hulud-Scanner.sh
            ./Mini-Shai-Hulud-Scanner.sh -q -o scan-report.txt .
        '''
        script {
            def threats = sh(script: "grep -c '^HASH_MATCH\\|^IOC_STRING\\|^MALICIOUS_FILENAME\\|^PERSISTENCE' scan-report.txt || true", returnStdout: true).trim()
            if (threats.toInteger() > 0) {
                error("THREATS DETECTED: ${threats} indicators found")
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'scan-report.txt', fingerprint: true
        }
    }
}
```

---

## Xử lý khi phát hiện threat

### Quy trình ứng phó

Khi script phát hiện `[THREAT]`, thực hiện theo trình tự sau:

```
┌─────────────────────────────────────────────────────────┐
│  1. CÔ LẬP                                              │
│  - Ngắt kết nối mạng của máy bị ảnh hưởng               │
│  - Dừng tất cả CI/CD pipeline đang chạy                  │
│  - Chụp ảnh/snapshot hệ thống để forensic                │
├─────────────────────────────────────────────────────────┤
│  2. XOAY CREDENTIALS                                    │
│  - npm tokens:  npm token list && npm token revoke <id> │
│  - GitHub PATs: Settings > Developer settings > Tokens  │
│  - AWS keys, GCP service accounts, Azure SP             │
│  - SSH keys trên tất cả máy                             │
│  - Database passwords, .env files                       │
├─────────────────────────────────────────────────────────┤
│  3. KIỂM TRA GITHUB                                     │
│  - gh repo list --public | grep -iE 'shai|hulud|kanly'  │
│  - Kiểm tra commit history: git log --all --author=...  │
│  - Xóa dead-drop repos nếu tìm thấy                     │
├─────────────────────────────────────────────────────────┤
│  3. VÔ HIỆU DEAD-MAN'S SWITCH (WAVE 4 — LÀM TRƯỚC!)    │
│  - Linux: systemctl --user stop gh-token-monitor        │
│  - macOS: launchctl unload ...gh-token-monitor.plist    │
│  - Xóa ~/.local/bin/gh-token-monitor.sh                 │
├─────────────────────────────────────────────────────────┤
│  4. DỌN SẠCH HỆ THỐNG                                  │
│  - Xóa file payload: setup.mjs, execution.js,           │
│    router_init.js, tanstack_runner.js, ...              │
│  - Xóa persistence: .claude/, .vscode/tasks.json,       │
│    .vscode/setup.mjs, codeql_analysis.yml               │
│  - Xóa node_modules và cài lại từ lock file sạch        │
│  - npm cache clean --force                               │
├─────────────────────────────────────────────────────────┤
│  5. KHÔI PHỤC                                           │
│  - Cài lại dependencies với --ignore-scripts             │
│  - Build lại từ source sạch                              │
│  - Quét lại lần nữa để xác nhận sạch                     │
│  - Khôi phục kết nối mạng                                │
├─────────────────────────────────────────────────────────┤
│  6. BÁO CÁO                                             │
│  - GitHub Security: https://github.com/security          │
│  - npm Security: security@npmjs.com                      │
│  - CISA (nếu tại Mỹ): https://www.cisa.gov/report       │
└─────────────────────────────────────────────────────────┘
```

### Lệnh khắc phục nhanh

```bash
# 1. Xoay npm tokens
npm token list
npm token revoke <each_token_id>
npm login   # tạo token mới

# 2. Kiểm tra và xóa GitHub dead-drop repos
gh repo list --public --limit 200 --json name,description | \
  jq -r '.[] | select(.description | test("Shai-Hulud|Mini Shai-Hulud")) | .name' | \
  while read repo; do gh repo delete "$repo" --confirm; done

# 0. VÔ HIỆU DEAD-MAN'S SWITCH TRƯỚC (Wave 4 — bắt buộc!)
systemctl --user stop gh-token-monitor.service 2>/dev/null
systemctl --user disable gh-token-monitor.service 2>/dev/null
launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist 2>/dev/null
rm -f ~/.config/systemd/user/gh-token-monitor.service
rm -f ~/.local/bin/gh-token-monitor.sh
rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist

# 3. Xóa malicious files
find / -type f \( -name "setup.mjs" -o -name "execution.js" -o -name "setup_bun.js" -o -name "bun_environment.js" -o -name "router_init.js" -o -name "tanstack_runner.js" \) -delete 2>/dev/null

# 4. Xóa persistence artifacts
find . -name ".claude" -exec rm -rf {} + 2>/dev/null
find . -path "*/.vscode/tasks.json" -delete 2>/dev/null
find . -path "*/.vscode/setup.mjs" -delete 2>/dev/null
find . -path "*/.github/workflows/format-check.yml" -delete 2>/dev/null
find . -path "*/.github/workflows/codeql_analysis.yml" -delete 2>/dev/null
find . -path "*/.github/workflows/discussion.yaml" -delete 2>/dev/null

# 5. Dọn npm cache và cài lại
npm cache clean --force
rm -rf node_modules package-lock.json
npm install --ignore-scripts
```

---

## Exit codes

| Exit code | Ý nghĩa | Hành động CI/CD |
|---|---|---|
| `0` | **Không phát hiện threat** — hệ thống sạch | Cho phép pipeline tiếp tục |
| `1-254` | **Phát hiện threat** — số lượng = exit code | Chặn pipeline, điều tra |
| `1` (error) | Lỗi kỹ thuật (thiếu dependency, thư mục không tồn tại) | Sửa pipeline config |

### Sử dụng exit code

```bash
# CI/CD — chặn pipeline nếu có threat
./Mini-Shai-Hulud-Scanner.sh -q /app || {
    echo "Deploy blocked: security scan found threats"
    exit 1
}

# Lấy số lượng threat
./Mini-Shai-Hulud-Scanner.sh /app
threat_count=$?
echo "Found $threat_count threats"

# Chỉ chặn nếu threat > 5 (ngưỡng tùy chỉnh)
./Mini-Shai-Hulud-Scanner.sh /app
if [ $? -gt 5 ]; then
    echo "CRITICAL: Too many threats"
    exit 1
fi
```

---

## FAQ

### Q: Wave 4 TanStack có gì khác biệt so với các wave trước?

Wave 4 (11/05/2026) là wave tinh vi nhất:

| Yếu tố | Wave 3 (SAP CAP) | Wave 4 (TanStack) |
|---|---|---|
| Vector chính | `preinstall` hook | `optionalDependencies` + `prepare` hook |
| Lấy quyền publish | Chiếm tài khoản npm | OIDC token từ Runner.Worker memory |
| Provenance | Không có | SLSA Build Level 3 hợp lệ giả mạo |
| C2 | GitHub dead-drop repos | Session P2P network (`filev2.getsession.org`) |
| Persistence | Claude Code + VS Code hooks | + Dead-man's switch systemd/launchd |
| Hủy diệt | Không | `rm -rf ~/` nếu token bị revoke |
| Phạm vi | 4 SAP packages | 42 @tanstack + ~120 worm-propagated |

### Q: Script chạy bao lâu?

**Full scan** thư mục `/` (toàn bộ hệ thống): 10-20 phút tùy dung lượng ổ đĩa (đã tối ưu hash lookup O(1) + IOC grep 1-pass từ v1.1.0).

**Quick scan** (`-q`) thư mục project trung bình: 3-10 giây.

### Q: Có an toàn để chạy trên production không?

Có. Script **chỉ đọc** — không sửa, không xóa, không di chuyển bất kỳ file nào. Tất cả output là read-only. Module process scan (`-p`) chỉ kiểm tra thông qua `ps`/`pgrep`, không can thiệp vào process.

### Q: Tại sao một số module bỏ qua `node_modules`?

Thư mục `node_modules` có thể chứa hàng trăm nghìn file, phần lớn là code third-party hợp pháp. Việc quét toàn bộ sẽ rất chậm và nhiễu. Tuy nhiên, nếu bạn nghi ngờ có package độc đã được cài vào `node_modules`, hãy quét không giới hạn:

```bash
# Ép quét node_modules bằng cách chỉ định trực tiếp
./Mini-Shai-Hulud-Scanner.sh ./node_modules
```

### Q: Làm sao để biết kết quả false positive?

Các trường hợp có thể gây false positive:

| Tình huống | Giải thích |
|---|---|
| File `setup.mjs` hợp pháp | Một số package dùng `setup.mjs` làm tên file init hợp pháp |
| Bun được cài qua package manager chính thức | Một số distro đã có Bun trong repo |
| Shell history > 10MB | Developer để history unlimited trong nhiều năm |

Luôn kiểm tra SHA-256 hash của file được flag — nếu hash **không** khớp với known-malicious hashes, đó là false positive.

### Q: Script có phát hiện được variant mới không?

Script dựa trên known IOCs, nên **không** phát hiện được variant chưa biết. Tuy nhiên, các module heuristic (large JS files, preinstall/prepare scripts, persistence artifacts, process chain, dead-man's switch services) có thể phát hiện hành vi đáng ngờ ngay cả khi hash chưa có trong cơ sở dữ liệu.

Script hiện tại bao phủ toàn bộ **4 wave tấn công** (09/2025 – 05/2026) với:
- **16** known-malicious SHA-256 hashes
- **22** IOC strings
- **7** malicious filenames  
- **13** persistence paths
- **20+** compromised version checks

Luôn cập nhật script khi có thông tin IOC mới từ:
- [CISA Alerts](https://www.cisa.gov/news-events/alerts)
- [Unit 42 Blog](https://unit42.paloaltonetworks.com/)
- [JFrog Blog](https://jfrog.com/blog/)
- [StepSecurity Blog](https://www.stepsecurity.io/blog/)
- [Snyk Blog](https://snyk.io/blog/)
- [Endor Labs](https://www.endorlabs.com/learn/)

### Q: Tôi có thể chạy trên macOS không?

Script nhắm đến Linux nhưng có thể chạy trên macOS với một số điều chỉnh:
- `stat` trên macOS dùng format khác (`stat -f%z` thay vì `stat -c%s`)
- `sha256sum` → `shasum -a 256`
- Không có `dpkg`/`rpm`

Phiên bản macOS sẽ được phát triển trong tương lai.
