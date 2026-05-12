# Mini Shai-Hulud Scanner — Ý Nghĩa Hoạt Động Chi Tiết

> Tài liệu tạo ngày 2026-05-12 12:30 — Phân tích chuyên sâu cách hoạt động của từng module quét

---

## Mục lục

1. [Bối cảnh: Mã độc Mini Shai-Hulud là gì?](#bối-cảnh-mã-độc-mini-shai-hulud-là-gì)
2. [Tổng quan kiến trúc script](#tổng-quan-kiến-trúc-script)
3. [11 Module quét — Phân tích chuyên sâu](#11-module-quét--phân-tích-chuyên-sâu)
   - [Module 1: Quét hash file độc hại](#module-1-quét-hash-file-độc-hại)
   - [Module 2: Quét chuỗi IOC](#module-2-quét-chuỗi-ioc)
   - [Module 3: Quét tên file độc hại](#module-3-quét-tên-file-độc-hại)
   - [Module 4: File JavaScript kích thước bất thường](#module-4-file-javascript-kích-thước-bất-thường)
   - [Module 5: Kiểm tra script preinstall/prepare trong package.json](#module-5-kiểm-tra-script-preinstallprepare-trong-packagejson)
   - [Module 6: Phát hiện cơ chế persistence](#module-6-phát-hiện-cơ-chế-persistence)
   - [Module 7: Quét process đang chạy](#module-7-quét-process-đang-chạy)
   - [Module 8: Kiểm tra tài khoản GitHub](#module-8-kiểm-tra-tài-khoản-github)
   - [Module 9: Kiểm tra môi trường & chỉ báo hệ thống](#module-9-kiểm-tra-môi-trường--chỉ-báo-hệ-thống)
   - [Module 10: Kiểm tra phiên bản dependency bị compromise](#module-10-kiểm-tra-phiên-bản-dependency-bị-compromise)
   - [Module 11: Kiểm tra lộ credential](#module-11-kiểm-tra-lộ-credential)
4. [Luồng thực thi tổng thể](#luồng-thực-thi-tổng-thể)
5. [Cơ chế báo cáo](#cơ-chế-báo-cáo)
6. [Các chế độ quét](#các-chế-độ-quét)
7. [Quy trình xử lý khi phát hiện threat](#quy-trình-xử-lý-khi-phát-hiện-threat)

---

## Bối cảnh: Mã độc Mini Shai-Hulud là gì?

**Mini Shai-Hulud** (còn gọi là **Shai-Hulud**) là một chuỗi tấn công **supply chain** do nhóm **TeamPCP** thực hiện, nhắm vào hệ sinh thái **npm/Node.js** (và một phần PyPI). Mã độc lây nhiễm qua các package npm bị chiếm quyền publish, sử dụng nhiều kỹ thuật tinh vi:

- **Payload ẩn trong package hợp pháp**: Kẻ tấn công chiếm quyền publish các package phổ biến (SAP CAP, TanStack Router, Mistral AI SDK, OpenSearch...), tiêm payload vào `preinstall` / `prepare` / `optionalDependencies` scripts.
- **Cơ chế persistence đa lớp**: Cài hook vào Claude Code (`.claude/settings.json`), VS Code (`tasks.json`), GitHub Actions workflows (Dependabot impersonation, CodeQL injection).
- **Dead-man's switch (Wave 4)**: Nếu token bị revoke, mã độc sẽ xóa toàn bộ `$HOME` của nạn nhân. Trước khi xoay credentials, phải vô hiệu hóa cơ chế này trước.
- **Stealth C2 (Wave 4)**: Dùng Session P2P network (`filev2.getsession.org`) thay vì GitHub dead-drop repos như các wave trước.

Script này là công cụ **phát hiện** toàn diện, bao phủ toàn bộ 4 wave tấn công đã biết (09/2025 – 05/2026).

---

## Tổng quan kiến trúc script

Script được viết bằng **Bash >= 4.0**, tuân thủ nguyên tắc:

- **Read-only**: Tuyệt đối không sửa, xóa, hay di chuyển bất kỳ file nào trên hệ thống.
- **Modular**: 11 module quét độc lập, mỗi module tập trung vào một khía cạnh của attack chain.
- **O(1) hash lookup**: Sử dụng associative array để so khớp hash trong thời gian hằng số.
- **Single-pass IOC grep**: Tất cả 22 IOC strings được tổ hợp thành một regex alternation, chỉ cần một lần `grep` duy nhất trên toàn bộ file.

### Biến toàn cục chính

| Biến | Ý nghĩa |
|---|---|
| `SCAN_ROOT` | Thư mục gốc cần quét (bắt buộc, được resolve thành absolute path) |
| `REPORT_FILE` | Đường dẫn file report nếu dùng `-o` |
| `VERBOSE` | `=1` khi dùng `-v`: hiển thị chi tiết từng bước kể cả "not found" |
| `QUICK` | `=1` khi dùng `-q`: thu hẹp phạm vi quét file |
| `CHECK_PROCESS` | `=1` khi dùng `-p`: bật module quét process (Module 7) |
| `CHECK_GITHUB` | `=1` khi dùng `-g`: bật module quét GitHub (Module 8) |
| `FOUND_THREATS` | Bộ đếm số lượng threat phát hiện được, dùng làm exit code |

---

## 11 Module quét — Phân tích chuyên sâu

### Module 1: Quét hash file độc hại

**Hàm:** `scan_hashes()`

**Nguyên lý hoạt động:**

1. **Xây dựng associative array** (`HASH_MAP`) từ 20 known-malicious hashes (16 file + 4 tarball). Mỗi hash là key, value là `"malware"` hoặc `"tarball"`. Nhờ cấu trúc này, việc tra cứu có độ phức tạp **O(1)** — mỗi file chỉ cần 1 phép lookup.

2. **Thu thập danh sách file cần quét:**
   - **Quick mode (`-q`):** Chỉ quét `*.js`, `*.mjs`, `*.cjs`, `*.tgz` — đây là các định dạng file mà payload thường ẩn dưới. Bỏ qua toàn bộ file hệ thống và media.
   - **Full mode:** Quét tất cả file trừ `/proc`, `/sys`, `/dev` (các pseudo-filesystem của Linux).

3. **Với mỗi file:**
   - Tính `sha256sum` → trích xuất hash (trường đầu tiên của output).
   - Lookup hash trong `HASH_MAP`. Nếu khớp → `[THREAT]`.
   - Hiển thị thêm kích thước file (`stat`) để đối chiếu.

**Ý nghĩa:** Đây là module có độ chính xác cao nhất — SHA-256 là unique fingerprint. Nếu hash khớp, đó là **xác nhận dương tính chắc chắn**.

**Các hash quan trọng nhất:**
- `4066781fa...` — `setup.mjs` (Wave 3 SAP CAP entry point)
- `80a3d2877...` — `execution.js` (payload mbt, 11.6MB)
- `ab4fcadae...` — `router_init.js` (Wave 4 TanStack, 2.3MB)
- `2ec78d556...` — `tanstack_runner.js` (Wave 4 TanStack runner)
- `a3894003a...` — `setup_bun.js` (Shai-Hulud 2.0 entry point)

---

### Module 2: Quét chuỗi IOC

**Hàm:** `scan_ioc_strings()`

**Nguyên lý hoạt động:**

1. **Xây dựng regex alternation** từ 22 IOC strings. Mỗi chuỗi được escape các ký tự đặc biệt của regex (`[.*^$()+?{|`) bằng `sed`. Các chuỗi được nối với nhau bằng `|` tạo thành một pattern duy nhất.

2. **Một lần `grep` duy nhất** trên toàn bộ thư mục quét với `--include` filter giới hạn loại file: `*.js`, `*.mjs`, `*.json`, `*.ts`, `*.yml`, `*.yaml`, `*.sh`, `*.py`, `*.txt`, `*.md`. Đây là tối ưu quan trọng: thay vì 22 lần grep riêng lẻ, chỉ cần 1 lần duyệt file system.

3. **Khi phát hiện file khớp:** chạy `grep -n` lần thứ hai để xác định chính xác dòng nào và IOC nào đã khớp. Giới hạn 5 dòng đầu tiên mỗi file (`head -5`) để tránh output quá dài.

4. **Bỏ qua chính file report** (`$REPORT_FILE`) để tránh vòng lặp phát hiện chính mình.

**Các IOC string đáng chú ý:**

| IOC String | Ý nghĩa trong attack chain |
|---|---|
| `ctf-scramble-v2` | Marker của cipher dùng để obfuscate payload. Phiên bản v2 xuất hiện từ Wave 3 |
| `__DAEMONIZED` | Biến môi trường mà payload tự đặt để đánh dấu đã kích hoạt daemon mode |
| `tmp.987654321.lock` | Lockfile trong `/tmp` để payload tránh chạy trùng lặp |
| `dependabout/github_actions/format/` | Path pattern của branch giả mạo Dependabot dùng để đẩy code độc qua PR |
| `svksjrhjkcejg` | PBKDF2 salt của Wave 4 TanStack payload |
| `EveryBoiWeBuildIsAWormyBoi` | Tên chiến dịch nội bộ của TeamPCP (Wave 4) |
| `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` | Mô tả npm token dùng làm dead-man's switch đe dọa |
| `79ac49eedf774dd4b0cfa308722bc463cfe5885c` | Orphan commit hash trong repo `tanstack/router` chứa malicious `optionalDependencies` |
| `filev2.getsession.org` | Session P2P C2 server (Wave 4) |
| `api.masscan.cloud` | Secondary C2 server |
| `git-tanstack.com` | Domain do attacker kiểm soát, giả mạo TanStack |
| `litter.catbox.moe` | File hosting service dùng để lưu trữ payload (Wave 4 staging) |
| `router_init.js` / `tanstack_runner.js` | Tên file payload Wave 4 — xuất hiện trong `prepare` scripts |
| `gh-token-monitor` | Tên dead-man's switch service (Wave 4) |

---

### Module 3: Quét tên file độc hại

**Hàm:** `scan_filenames()`

**Nguyên lý hoạt động:**

- Duyệt qua danh sách 7 tên file đã biết (`setup.mjs`, `execution.js`, `setup_bun.js`, `bun_environment.js`, `bundle.js`, `router_init.js`, `tanstack_runner.js`).
- Với mỗi tên file, chạy `find -name` trong `SCAN_ROOT`, bỏ qua `node_modules/.cache`.
- Khi tìm thấy: hiển thị kích thước + SHA-256 hash để đối chiếu với known hashes.

**Tại sao cần module riêng biệt với Module 1?**

Module 1 dựa trên hash (chính xác tuyệt đối). Module 3 dựa trên filename (heuristic). File có tên `setup.mjs` có thể là file hợp pháp của một package khác. Nhưng việc flag theo tên giúp **phát hiện variant mới** của attacker (cùng tên file nhưng hash khác do thay đổi payload).

**Loại bỏ false positive:** Khi module này flag một file, cần kiểm tra hash của file đó. Nếu hash **có** trong known hashes → xác nhận dương tính. Nếu hash **không** có → có thể là false positive, cần điều tra thêm.

---

### Module 4: File JavaScript kích thước bất thường

**Hàm:** `scan_large_js()`

**Nguyên lý hoạt động:**

1. **Tìm file JS > 9MB:** Dùng `find -size +9M` với filter `*.js`, `*.mjs`, `*.cjs`, bỏ qua `node_modules`. Ngưỡng 9MB được chọn vì:
   - `execution.js` của Wave 3 khoảng **11.6 MB**
   - `bun_environment.js` của Wave 2 >= **9 MB**
   - File JS thông thường hiếm khi vượt quá 1-2 MB

2. **Kiểm tra bổ sung cho mỗi file lớn:**
   - Có chứa `ctf-scramble-v2` không? → Dấu hiệu obfuscation cipher.
   - Có tham chiếu đến `oven-sh/bun/releases` không? → Dấu hiệu download Bun runtime (để chạy payload).

**Ý nghĩa chiến thuật:** Đây là module **heuristic** — không dựa trên hash hay IOC cụ thể, mà dựa trên đặc điểm vật lý của payload. Attacker có thể thay đổi nội dung payload, nhưng kích thước lớn (do chứa toàn bộ mã obfuscate + logic C2) là đặc điểm khó che giấu.

---

### Module 5: Kiểm tra script preinstall/prepare trong package.json

**Hàm:** `scan_preinstall()`

Đây là module phức tạp nhất, phát hiện **vector lây nhiễm chính** của tất cả các wave.

**Nguyên lý hoạt động:**

1. **Tìm tất cả `package.json`** trong `SCAN_ROOT` (bỏ qua `node_modules/.cache`).

2. **Với mỗi `package.json`:**
   - Dùng `jq` để trích xuất `scripts.preinstall` và `scripts.prepare`.
   - Kiểm tra nội dung script có chứa chuỗi nguy hiểm không: `setup.mjs`, `execution.js`, `curl.*bun`, `wget.*bun`, `bun.*run.*tanstack_runner`, `bun.*run.*router_init`.
   - Nếu `prepare` hook có pattern `&& exit 1` → flag là đáng ngờ (Wave 4 dùng pattern này để cài payload rồi fail quá trình install, che giấu hành vi).

3. **Kiểm tra `optionalDependencies` (Wave 4 TanStack specific):**
   - Wave 4 không dùng `preinstall` mà lợi dụng `optionalDependencies` với URL `github:tanstack/router#<commit-hash>`.
   - npm sẽ tự động clone repo và chạy `prepare` hook của package đó.
   - Script kiểm tra sự hiện diện của commit hash `79ac49eedf774dd4b0cfa308722bc463cfe5885c` hoặc pattern `github:tanstack/router`.

4. **Đối chiếu version với danh sách đen:**
   - Kiểm tra `name` + `version` của package với danh sách compromised versions đã biết.
   - Phân biệt theo wave: Wave 3 (SAP CAP), Wave 4 (TanStack, Mistral, OpenSearch).
   - Mỗi package bị flag với thông tin version cụ thể (ví dụ: `@tanstack/react-router@1.169.5` hoặc `1.169.8`).

**Các package bị compromise đã biết (Wave 4 TanStack):**

| Package | Versions độc |
|---|---|
| `@tanstack/react-router` | 1.169.5, 1.169.8 |
| `@tanstack/vue-router` | 1.169.5, 1.169.8 |
| `@tanstack/solid-router` | 1.169.5, 1.169.8 |
| `@tanstack/router-core` | 1.169.5, 1.169.8 |
| `@tanstack/react-start` | 1.167.68, 1.167.71 |
| `@tanstack/router-plugin` | 1.167.38, 1.167.41 |
| `@tanstack/router-cli` | 1.166.46, 1.166.49 |
| `@tanstack/history` | 1.161.9, 1.161.12 |
| `@mistralai/mistralai` | 2.2.3, 2.2.4 |
| `@mistralai/mistralai-azure` | 1.7.2, 1.7.3 |
| `@mistralai/mistralai-gcp` | 1.7.2, 1.7.3 |
| `@opensearch-project/opensearch` | 3.6.2 |

**Wave 3 (SAP CAP):**

| Package | Version độc |
|---|---|
| `mbt` | 1.2.48 |
| `@cap-js/db-service` | 2.10.1 |
| `@cap-js/sqlite` | 2.2.2 |
| `@cap-js/postgres` | 2.2.2 |

---

### Module 6: Phát hiện cơ chế persistence

**Hàm:** `scan_persistence()`

**Nguyên lý hoạt động:**

Module này quét các vị trí mà payload cài cơ chế tự động chạy lại sau khi hệ thống khởi động hoặc khi mở project. Phạm vi quét:
- `$HOME` của user hiện tại
- `$SCAN_ROOT`
- Nếu chạy với `sudo` (EUID=0): quét thêm tất cả `/home/*`

**Các persistence path và cách kiểm tra:**

| Persistence Path | Cơ chế | Cách phát hiện |
|---|---|---|
| `.claude/settings.json` | Hook `SessionStart` của Claude Code — chạy mỗi khi mở Claude Code | Dùng `jq` kiểm tra key `hooks.SessionStart` |
| `.vscode/tasks.json` | VS Code task `runOn: folderOpen` — chạy khi mở project | Dùng `jq` kiểm tra `tasks[].runOn == "folderOpen"` |
| `.github/workflows/format-check.yml` | Workflow GitHub Actions giả mạo Dependabot | `grep -c "toJSON(secrets)"` — exfiltrate secrets |
| `.github/workflows/codeql_analysis.yml` | Wave 4 injected workflow giả mạo CodeQL | `grep -c "toJSON(secrets)"` — tương tự Dependabot |
| `.github/workflows/discussion.yaml` | Workflow đăng ký self-hosted runner với tên `SHA1HULUD` | Kiểm tra file tồn tại |
| `.claude/router_runtime.js` | Wave 4 payload tự copy vào `.claude/` | Kiểm tra file tồn tại |
| `.claude/setup.mjs` | Wave 4 ESM loader shim | Kiểm tra file tồn tại |
| `.vscode/setup.mjs` | Wave 4 VS Code payload | Kiểm tra file tồn tại |
| `.local/bin/gh-token-monitor.sh` | Wave 4 dead-man's switch script (Linux) | Kiểm tra file tồn tại |
| `.config/systemd/user/gh-token-monitor.service` | Wave 4 systemd service tự khởi động (Linux) | Kiểm tra file tồn tại |
| `Library/LaunchAgents/com.user.gh-token-monitor.plist` | Wave 4 LaunchAgent (macOS) | Kiểm tra file tồn tại |

**Tại sao dead-man's switch nguy hiểm?**

File `gh-token-monitor.sh` định kỳ kiểm tra trạng thái GitHub token. Nếu token bị revoke, script sẽ thực thi `rm -rf ~/` — xóa toàn bộ home directory. **Vì vậy, trước khi revoke token, phải vô hiệu hóa service này trước.**

---

### Module 7: Quét process đang chạy

**Hàm:** `scan_processes()` — **chỉ chạy khi có flag `-p`**

**Nguyên lý hoạt động:**

1. **Phát hiện process chain `node → bun → python`:**
   - Dùng `pgrep -f bun` để tìm tất cả Bun processes.
   - Với mỗi Bun process, kiểm tra parent process (`ps -o ppid`).
   - Nếu parent là `node` hoặc `npm` → đây là chuỗi lây nhiễm điển hình: npm package chạy preinstall script → gọi `node` → `node` spawn `bun` → `bun` chạy payload Python.

2. **Kiểm tra biến môi trường `__DAEMONIZED`:** Payload tự đặt biến này để đánh dấu daemon mode đã active.

3. **Kiểm tra lockfile `/tmp/tmp.987654321.lock`:** Payload tạo file này để tránh chạy nhiều instance cùng lúc.

4. **Kiểm tra GitHub Actions runner `SHA1HULUD`:** Self-hosted runner được đăng ký với tên này để attacker có thể chạy workflow trên máy nạn nhân.

---

### Module 8: Kiểm tra tài khoản GitHub

**Hàm:** `scan_github()` — **chỉ chạy khi có flag `-g`**

**Nguyên lý hoạt động:**

1. **Xác thực:** Kiểm tra `gh auth status`. Nếu chưa đăng nhập, báo lỗi và dừng module này.

2. **Tìm dead-drop repos:** Liệt kê tối đa 200 public repos, lọc những repo có description chứa pattern `Mini Shai-Hulud`, `Shai-Hulud`, `Sha1-Hulud`. Đây là cách attacker dùng GitHub như kênh C2: tạo public repo với tên ngẫu nhiên (theo Dune lexicon), payload định kỳ tìm kiếm repo có description đặc biệt để nhận lệnh.

3. **Tìm suspicious commits:** Dùng GitHub Search API tìm commits từ author `claude@users.noreply.github.com` từ tháng 3/2026. Wave 4 sử dụng Claude Code để tự động tạo commits với danh tính giả.

---

### Module 9: Kiểm tra môi trường & chỉ báo hệ thống

**Hàm:** `scan_environment()`

**Nguyên lý hoạt động:**

1. **Biến môi trường:**
   - `__DAEMONIZED` → threat (malware marker).
   - `NPM_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN` → warn (token có thể bị đánh cắp nếu máy đã bị compromise).

2. **Bun binary đáng ngờ:** Nếu Bun tồn tại nhưng **không** được cài qua `dpkg` hoặc `rpm` → có thể payload đã tự download Bun runtime.

3. **npm cache:** Tìm hash của 4 known-malicious tarballs trong `~/.npm/_cacache`. Nếu tarball độc từng được cài, dấu vết vẫn còn trong cache.

4. **npm token đe dọa (Wave 4):** Dùng `npm token list` kiểm tra token có description `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` → dead-man's switch.

5. **Dead-man's switch services:**
   - `~/.config/systemd/user/gh-token-monitor.service` (Linux systemd)
   - `~/Library/LaunchAgents/com.user.gh-token-monitor.plist` (macOS)
   - `~/.local/bin/gh-token-monitor.sh` (script)

---

### Module 10: Kiểm tra phiên bản dependency bị compromise

**Hàm:** `scan_dependency_versions()`

**Nguyên lý hoạt động:**

1. **Tìm lock files:** `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` trong `SCAN_ROOT` (giới hạn depth=4, bỏ qua `node_modules`).

2. **Đối chiếu từng package trong danh sách đen với lock file:**
   - Dùng `grep` tìm tên package và version trong lock file.
   - Nếu cả tên package và version độc đều xuất hiện → `[THREAT]`.
   - Nếu tên package xuất hiện nhưng version khác → `[WARN]` (cần điều tra thêm).

**Danh sách package trong module này (có thể khác với Module 5):**

Module 5 kiểm tra `package.json` trực tiếp (phiên bản đang khai báo). Module 10 kiểm tra lock files (phiên bản đã resolved, chính xác hơn cho CI/CD audit). Cả hai module bổ trợ cho nhau.

---

### Module 11: Kiểm tra lộ credential

**Hàm:** `scan_credential_exposure()`

**Nguyên lý hoạt động:**

1. **Kiểm tra permissions của file credential:**
   - SSH keys (`~/.ssh/id_*`) phải có permissions `600` hoặc `400`.
   - Certificate files (`*.pem`, `*.p12`, `*.pfx`) cũng cần permissions an toàn.
   - Permissions yếu (ví dụ `644`) → file có thể bị đọc bởi process khác → dấu hiệu đã bị exfiltration.

2. **Kiểm tra kích thước shell history:**
   - `.bash_history`, `.zsh_history`, `.mysql_history`, `.psql_history`, `.rediscli_history`.
   - Nếu > 10MB → bất thường. Payload có thể đã inject commands vào history để che giấu hoặc history bị exfiltrate.

---

## Luồng thực thi tổng thể

```
main()
  │
  ├── In banner + thông tin scan (root, time, mode)
  ├── Khởi tạo report file (nếu có -o)
  ├── check_deps()          — Kiểm tra tool cần thiết: sha256sum, find, grep, jq, stat
  │                           (gh CLI chỉ kiểm tra nếu -g được dùng)
  │
  ├── scan_hashes()         — Module 1: Quét hash (O(1) lookup)
  ├── scan_ioc_strings()    — Module 2: Quét chuỗi IOC (single-pass grep)
  ├── scan_filenames()      — Module 3: Quét tên file độc
  ├── scan_large_js()       — Module 4: File JS > 9MB
  ├── scan_preinstall()     — Module 5: Preinstall/prepare/optionalDeps audit
  ├── scan_persistence()    — Module 6: Persistence artifacts
  ├── scan_processes()      — Module 7: Process chain (chỉ với -p)
  ├── scan_github()         — Module 8: GitHub dead-drop (chỉ với -g)
  ├── scan_environment()    — Module 9: Env vars, Bun, npm cache, dead-man's switch
  ├── scan_dependency_versions() — Module 10: Lock file version check
  ├── scan_credential_exposure() — Module 11: Credential permissions & history size
  │
  └── In kết quả tổng hợp:
        - FOUND_THREATS == 0 → "NO THREATS DETECTED"
        - FOUND_THREATS > 0  → "!! THREATS DETECTED !!" + hướng dẫn ứng phó
        - Exit code = FOUND_THREATS
```

Tất cả 11 module **luôn chạy tuần tự**. Không có module nào dừng sớm khi phát hiện threat — điều này đảm bảo thu thập được bức tranh toàn cảnh về mức độ xâm nhập.

---

## Cơ chế báo cáo

### Output ra terminal

Sử dụng **mã màu ANSI** để phân biệt mức độ nghiêm trọng:

| Tag | Màu | Ý nghĩa | Hành động cần làm |
|---|---|---|---|
| `[THREAT]` | Đỏ đậm | Xác nhận dương tính — IOC khớp chính xác | Hành động ngay lập tức |
| `[WARN]` | Vàng | Dấu hiệu đáng ngờ — cần điều tra thêm | Kiểm tra thủ công |
| `[INFO]` | Cyan | Trạng thái quét | Không cần hành động |
| `[OK]` | Xanh | Hạng mục sạch | Không cần hành động |
| `[ERROR]` | Đỏ | Lỗi kỹ thuật (thiếu tool, không đọc được file) | Sửa pipeline config |

### Report file (với `-o`)

Định dạng **pipe-delimited** để dễ dàng parse bằng script:

```
HASH_MATCH|<sha256>|<file_path>|<file_size>
IOC_STRING|<file_path>|<line_number>|<line_content>
MALICIOUS_FILENAME|<filename>|<file_path>|<file_size>|<sha256>
LARGE_JS|<file_path>|<file_size>|<sha256>
PREINSTALL_SCRIPT|<pkg_name>|<pkg_version>|<script_content>|<file_path>
WAVE4_PREPARE_HOOK|<pkg_name>|<pkg_version>|<script_content>|<file_path>
WAVE4_OPTIONAL_DEP|<pkg_name>|<dep_spec>|<file_path>
PERSISTENCE_CLAUDE_HOOK|<file_path>|<hook_content>
PERSISTENCE_VSCODE_TASK|<file_path>|<task_command>
PERSISTENCE_DEPENDABOT_WORKFLOW|<file_path>
PERSISTENCE_CODEQL_WORKFLOW|<file_path>
PERSISTENCE_WAVE4_PAYLOAD|<file_path>
PERSISTENCE_DEADMAN_SWITCH|<file_path>
PROCESS_BUN_SPAWN|<pid>|<ppid>|<parent_cmd>
ENV_DAEMONIZED|set
LOCKFILE|<path>
GITHUB_DEADDROP_REPO|<repo_info>
GITHUB_SUSPICIOUS_COMMITS|<count>
ENV_MALWARE|<var_name>
ENV_SENSITIVE|<var_name>
BUN_INSTALLED|<bun_path>
NPM_CACHE_THREAT|<tarball_hash>|<cache_path>
WAVE4_THREAT_TOKEN|<token_info>
WAVE4_SYSTEMD_SERVICE|<path>
WAVE4_LAUNCHAGENT|<path>
WAVE4_MONITOR_SCRIPT|<path>
LOCKFILE_COMPROMISED|<pkg_spec>|<lockfile_path>
LOCKFILE_SUSPICIOUS|<pkg_name>|<lockfile_path>
CRED_WEAK_PERMS|<file_path>|<permissions>
LARGE_HISTORY|<file_path>|<file_size>
```

### Cách parse report

```bash
# Đếm số lượng từng loại threat
cut -d'|' -f1 scan-report.txt | grep -v '^#' | sort | uniq -c | sort -rn

# Trích xuất tất cả file path bị ảnh hưởng
grep -E '^(HASH_MATCH|IOC_STRING|MALICIOUS_FILENAME|LARGE_JS)' scan-report.txt | cut -d'|' -f3 | sort -u

# Lọc riêng các threat (bỏ qua warn/info)
grep -v '^#' scan-report.txt | grep -v 'WARN'
```

---

## Các chế độ quét

### Full Scan (mặc định)

- Quét **tất cả file** trong `SCAN_ROOT` (trừ `/proc`, `/sys`, `/dev`).
- Thời gian: vài phút đến hàng giờ tùy dung lượng ổ đĩa.
- Phù hợp: audit định kỳ, điều tra sự cố (incident response).

### Quick Scan (`-q`)

- Module 1 (hash) chỉ quét `*.js`, `*.mjs`, `*.cjs`, `*.tgz`.
- Các module khác không bị ảnh hưởng.
- Thời gian: vài giây đến vài phút.
- Phù hợp: CI/CD pipeline, quét nhanh trước khi deploy.
- Rủi ro: có thể bỏ sót payload được đổi tên thành đuôi file khác.

### Process Check (`-p`)

- Bật Module 7 (quét process đang chạy).
- Cần `pgrep` (tự động bỏ qua nếu không có).
- Không ảnh hưởng đến các module khác.

### GitHub Check (`-g`)

- Bật Module 8 (quét GitHub account).
- Cần `gh` CLI + đã xác thực (`gh auth login`).
- Không ảnh hưởng đến các module khác.
- Yêu cầu kết nối internet.

### Verbose (`-v`)

- Hiển thị chi tiết từng bước, kể cả "No IOC strings found", "No files named X found".
- Hữu ích cho forensic audit.

### Kết hợp nhiều flag

```bash
# Quét đầy đủ nhất: file + process + GitHub + report
./Mini-Shai-Hulud-Scanner.sh -p -g -v -o forensic-report.txt /home/user

# Quick scan cho CI/CD + process check
./Mini-Shai-Hulud-Scanner.sh -q -p -o ci-scan.txt "$CI_PROJECT_DIR"

# Full system scan với sudo
sudo ./Mini-Shai-Hulud-Scanner.sh -p -o /var/log/scan.txt /
```

---

## Quy trình xử lý khi phát hiện threat

Khi script phát hiện `[THREAT]`, thứ tự hành động **quan trọng**:

### Bước 0: Cô lập máy (trước tất cả)
- Ngắt kết nối mạng.
- Dừng CI/CD pipelines.
- Snapshot hệ thống để forensic.

### Bước 1: Vô hiệu dead-man's switch (Wave 4 — làm trước khi revoke token!)

```bash
# Linux
systemctl --user stop gh-token-monitor.service
systemctl --user disable gh-token-monitor.service
rm -f ~/.config/systemd/user/gh-token-monitor.service
rm -f ~/.local/bin/gh-token-monitor.sh

# macOS
launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
```

### Bước 2: Xoay credentials
- npm tokens: `npm token list && npm token revoke <id>`
- GitHub PATs
- Cloud API keys (AWS, GCP, Azure)
- SSH keys
- Database passwords

### Bước 3: Dọn dẹp persistence
- Xóa `.claude/` directory, `.vscode/tasks.json`, `.vscode/setup.mjs`
- Xóa `.github/workflows/format-check.yml`, `codeql_analysis.yml`, `discussion.yaml`
- Xóa tất cả file payload (`setup.mjs`, `execution.js`, `router_init.js`, `tanstack_runner.js`, ...)
- `npm cache clean --force`

### Bước 4: Khôi phục
- Cài lại dependencies với `npm install --ignore-scripts`
- Build lại từ source sạch
- Quét lại để xác nhận hệ thống sạch
- Khôi phục kết nối mạng

---

## Tổng kết

**Mini-Shai-Hulud-Scanner.sh** v1.1.0 là công cụ phát hiện toàn diện, bao phủ toàn bộ attack chain của 4 wave tấn công supply chain Mini Shai-Hulud / Shai-Hulud (09/2025 – 05/2026). Với 11 module quét độc lập, script kiểm tra từ file payload, IOC strings, persistence, process, GitHub dead-drop, cho đến dead-man's switch services. Script hoạt động theo nguyên tắc read-only, an toàn để chạy trên production, và phù hợp cho cả audit thủ công lẫn tích hợp CI/CD tự động.
