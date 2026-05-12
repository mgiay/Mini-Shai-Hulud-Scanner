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

**Mini-Shai-Hulud-Scanner.sh** là công cụ dòng lệnh dành cho Linux, quét và phát hiện dấu vết của mã độc Mini Shai-Hulud / Shai-Hulud — chuỗi tấn công supply chain nhắm vào hệ sinh thái npm/Node.js từ tháng 9/2025 đến nay.

Script thực hiện 11 module quét độc lập, bao phủ toàn bộ attack chain: từ file payload trên đĩa, IOC strings, persistence mechanism, cho đến process đang chạy và GitHub dead-drop repos.

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
| `du` | Có | Phân tích dung lượng |
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
| `dependabout/github_actions/format/setup-formatter` | Branch typosquat Dependabot |
| `cloudmtabot` | Tài khoản npm bị compromise |

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

### Module 5: Suspicious Preinstall Script Audit

**Mục đích:** Phát hiện `preinstall` scripts độc hại trong `package.json` — vector lây nhiễm chính.

**Cách hoạt động:**
1. Tìm tất cả file `package.json` trong thư mục quét
2. Trích xuất `scripts.preinstall` nếu có
3. Cảnh báo các script tham chiếu đến file độc (`setup.mjs`, `execution.js`) hoặc download Bun runtime
4. Đối chiếu `name` + `version` với danh sách package đã biết là độc

**Danh sách version bị flag:**

| Package | Version độc |
|---|---|
| `mbt` | 1.2.48 |
| `@cap-js/db-service` | 2.10.1 |
| `@cap-js/sqlite` | 2.2.2 |
| `@cap-js/postgres` | 2.2.2 |

**Kết quả đầu ra khi phát hiện:**
```
[WARN]  Package [my-package@1.0.0] has preinstall script: node setup.mjs
[THREAT]   -> DANGEROUS: preinstall references known malicious file or downloads Bun
[THREAT] COMPROMISED VERSION: @cap-js/sqlite@2.2.2 in /project/package.json
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

**Phạm vi quét:**
- `$HOME` của user hiện tại
- Thư mục `$SCAN_ROOT`
- Nếu chạy với `sudo` (root): quét thêm tất cả thư mục `/home/*`

**Kết quả đầu ra khi phát hiện:**
```
[THREAT] Claude Code SessionStart hook: /home/user/project/.claude/settings.json
[THREAT] VS Code folderOpen task: /home/user/project/.vscode/tasks.json -> node /tmp/payload.js
[THREAT] Dependabot impersonation workflow (secrets dump): /home/user/project/.github/workflows/format-check.yml
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

**Kết quả đầu ra khi phát hiện:**
```
[THREAT] Malware daemon env var set: __DAEMONIZED
[WARN]  Sensitive token in environment: GH_TOKEN (consider unsetting)
[WARN]  Bun runtime found at: /usr/local/bin/bun
[WARN]    -> Bun was NOT installed via system package manager
[THREAT] Known malicious tarball found in npm cache: 0af7415d6575...
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
[THREAT] Compromised package in lockfile: mbt@1.2.48 in /project/package-lock.json (Mini Shai-Hulud, April 2026)
[WARN]  Potentially compromised package: @ctrl/tinycolor in /project/yarn.lock (Shai-Hulud 2.0, November 2025)
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
│  4. DỌN SẠCH HỆ THỐNG                                  │
│  - Xóa file payload: setup.mjs, execution.js, ...       │
│  - Xóa persistence: .claude/settings.json, .vscode/...   │
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

# 3. Xóa malicious files
find / -type f \( -name "setup.mjs" -o -name "execution.js" -o -name "setup_bun.js" -o -name "bun_environment.js" \) -delete 2>/dev/null

# 4. Xóa persistence artifacts
find . -name ".claude" -exec rm -rf {} + 2>/dev/null
find . -path "*/.vscode/tasks.json" -delete 2>/dev/null
find . -path "*/.github/workflows/format-check.yml" -delete 2>/dev/null
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

### Q: Script chạy bao lâu?

**Full scan** thư mục `/` (toàn bộ hệ thống): 10-60 phút tùy dung lượng ổ đĩa.

**Quick scan** (`-q`) thư mục project trung bình: 5-30 giây.

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

Script dựa trên known IOCs, nên **không** phát hiện được variant chưa biết. Tuy nhiên, các module heuristic (large JS files, preinstall scripts, persistence artifacts, process chain) có thể phát hiện hành vi đáng ngờ ngay cả khi hash chưa có trong cơ sở dữ liệu.

Luôn cập nhật script khi có thông tin IOC mới từ:
- [CISA Alerts](https://www.cisa.gov/news-events/alerts)
- [Unit 42 Blog](https://unit42.paloaltonetworks.com/)
- [JFrog Blog](https://jfrog.com/blog/)
- [StepSecurity Blog](https://www.stepsecurity.io/blog/)

### Q: Tôi có thể chạy trên macOS không?

Script nhắm đến Linux nhưng có thể chạy trên macOS với một số điều chỉnh:
- `stat` trên macOS dùng format khác (`stat -f%z` thay vì `stat -c%s`)
- `sha256sum` → `shasum -a 256`
- Không có `dpkg`/`rpm`

Phiên bản macOS sẽ được phát triển trong tương lai.
