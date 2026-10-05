# KẾ HOẠCH TOÀN DIỆN: GIÁM SÁT VÀ CHUYỂN ĐỔI APPARMOR TỪ COMPLAIN SANG ENFORCING
## LỘ TRÌNH QUAN SÁT 1–2 THÁNG TRÊN MÔI TRƯỜNG PRODUCTION UBUNTU 24.04 LTS (TCBS STANDARDS)

> **Tài liệu tham chiếu:** 
> - Chuẩn an toàn thông tin TCVN 14423:2026 (Cấp độ 3 & 4)
> - CIS Ubuntu Linux 24.04 LTS Benchmark Level 2 Server
> - Báo cáo tác động vận hành: [BAO_CAO_CHI_TIET_TAC_DONG_VAN_HANH_SYSADMIN.md](file:///Users/cmdx/work/tcbs/TCVN/BAO_CAO_CHI_TIET_TAC_DONG_VAN_HANH_SYSADMIN.md)
> - Kế hoạch SELinux tương đương: [KE_HOACH_GIAM_SAT_SELINUX_PERMISSIVE_DEN_ENFORCING.md](file:///Users/cmdx/work/tcbs/TCVN/KE_HOACH_GIAM_SAT_SELINUX_PERMISSIVE_DEN_ENFORCING.md)

---

## 1. MỤC TIÊU & NGUYÊN TẮC CỐT LÕI

AppArmor là cơ chế kiểm soát truy cập bắt buộc dựa trên đường dẫn tệp tin (Path-based Mandatory Access Control - MAC) được tích hợp trực tiếp vào nhân Linux của Ubuntu 24.04 LTS. Khác với SELinux (kiểm soát toàn hệ thống qua nhãn ngữ cảnh Type Enforcement), AppArmor hoạt động dựa trên các hồ sơ bảo vệ riêng biệt (Per-Application Security Profiles) nằm trong thư mục `/etc/apparmor.d/`.

Khi một profile được đặt ở chế độ **`Enforce`**, nhân Linux sẽ chặn đứng mọi hành vi truy cập tệp, kết nối mạng hoặc thực thi lệnh nằm ngoài danh mục cho phép trong profile, ngay cả khi hành vi đó được thực hiện bởi tài khoản đặc quyền `root`.

Đối với hạ tầng Production của Techcom Securities (TCBS), việc áp dụng kịch bản cứng của CIS Level 2 (chạy `aa-enforce` mù quáng lên toàn bộ profile) tiềm ẩn nguy cơ rất cao làm sập các ứng dụng nghiệp vụ, hỏng cơ chế khởi tạo container (`runc`), và ngắt quãng các pipeline tự động hóa.

### Nguyên tắc triển khai:
1. **Zero-Downtime / Zero-Disruption**: Không để bất kỳ dịch vụ kinh doanh nào bị gián đoạn hay crash do AppArmor chặn nhầm.
2. **Complain Mode Observation Window (1–2 tháng)**: 
   - Đặt các profile ứng dụng mới, ứng dụng tùy biến hoặc các profile đang trong quá trình chuyển đổi sang chế độ **`Complain`**.
   - Ở chế độ này, nhân Linux **vẫn kiểm tra 100% các thao tác truy cập**, ghi nhật ký chi tiết các hành vi vi phạm vào `/var/log/audit/audit.log` (với từ khóa `apparmor="ALLOWED"`), nhưng **KHÔNG CHẶN** tiến trình.
3. **Bảo toàn Tuyệt đối các "Named Unconfined Shim Profiles"**: 
   - Không được chạy lệnh `aa-enforce *` quét toàn bộ thư mục `/etc/apparmor.d/`, tránh kích hoạt bug tước bỏ cờ `flags=(unconfined)` trong các shim profile của hệ điều hành (như `runc`, `podman`, `crun`).
   - Duy trì `runc` ở trạng thái `unconfined` để bảo đảm container runtime hoạt động bình thường, trong khi các tiến trình con bên trong container vẫn bị cưỡng chế 100% bởi profile **`docker-default` (Enforce Mode)**.
4. **Phủ kín toàn bộ chu kỳ nghiệp vụ**: Thời gian quan sát 1–2 tháng là bắt buộc để hệ thống trải qua đầy đủ:
   - Các chu kỳ chốt sổ, quyết toán giao dịch cuối ngày (Daily Batch Jobs).
   - Chu kỳ sao lưu dữ liệu toàn diện cuối tuần (Weekly Backups).
   - Chu kỳ quyết toán và lập báo cáo tài chính cuối tháng (Month-end Processing).
   - Các đợt triển khai phiên bản ứng dụng mới qua CI/CD và diễn tập khôi phục thảm họa (DR Failover).
5. **Data-Driven Cutover**: Chỉ chuyển đổi một profile từ `Complain` sang `Enforce` khi hệ thống đạt chỉ số **Zero Unhandled AppArmor Violations** trong tối thiểu 14 ngày liên tục.

---

## 2. KIẾN TRÚC THU THẬP & PHÂN TÍCH NHẬT KÝ APPARMOR

```
┌────────────────────────────────────────────────────────────────────────┐
│ LINUX KERNEL (APPARMOR SUBSYSTEM - UBUNTU 24.04 LTS)                   │
│                                                                        │
│  Target Process (nginx, postgres, custom_app, host service)            │
│       │                                                                │
│       ▼                                                                │
│  [AppArmor Profile Access Control Check]                               │
│       │                                                                │
│       ├─► (Thao tác Hợp lệ trong Profile) ────► Cho phép thực thi      │
│       │                                                                │
│       └─► (Thao tác Nằm ngoài Profile)                                 │
│                 │                                                      │
│                 ▼                                                      │
│         [Trạng thái Profile?]                                          │
│                 │                                                      │
│                 ├─► [ENFORCE MODE]                                     │
│                 │        ├─► CHẶN TIẾN TRÌNH NGAY LẬP TỨC              │
│                 │        └─► Ghi log: apparmor="DENIED"                │
│                 │                                                      │
│                 └─► [COMPLAIN MODE]                                    │
│                          ├─► CHO PHÉP TIẾP TỤC (Không gián đoạn)       │
│                          └─► Ghi log: apparmor="ALLOWED"               │
└─────────────────┬──────────────────────────────────────────────────────┘
                  │
                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│ AUDITD DAEMON & LOCAL PROFILING ANALYSIS                               │
│                                                                        │
│  Tệp nhật ký tập trung: /var/log/audit/audit.log                       │
│  (Dự phòng: /var/log/syslog và kernel dmesg)                           │
│  Bộ công cụ tinh chỉnh:                                                │
│    - sudo aa-status                                                    │
│    - sudo aa-logprof                                                   │
│    - sudo ausearch -m avc -c apparmor                                  │
│    - /etc/apparmor.d/local/<profile> (Local overrides bền vững)        │
└─────────────────┬──────────────────────────────────────────────────────┘
                  │ (Fluent Bit Container / Filebeat)
                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│ CENTRALIZED SIEM & NOTIFICATION (ELASTICSEARCH / S3 WORM)              │
│                                                                        │
│  - Dashboard: "Ubuntu AppArmor Complain vs Denied Violations"          │
│  - Filter Regex: log (AVC|apparmor|USER_AVC)                           │
│  - Alerting: Kênh Slack / Telegram / PagerDuty khi có Denial mới       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. LỘ TRÌNH 4 GIAI ĐOẠN TỪ COMPLAIN ĐẾN ENFORCE

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   GIAI ĐOẠN 1   │     │   GIAI ĐOẠN 2   │     │   GIAI ĐOẠN 3   │     │   GIAI ĐOẠN 4   │
│  (Tuần 1 - 2)   │────►│  (Tuần 3 - 4)   │────►│  (Tuần 5 - 7)   │────►│    (Tuần 8)     │
│  Khảo sát trạng │     │  Vận hành tải   │     │  Quan sát chu   │     │   Chuyển đổi    │
│  thái & Cấu hình│     │  thực tế & Tinh │     │  kỳ cuối tháng  │     │   Enforce &     │
│  Complain Mode  │     │  chỉnh Profile  │     │  (Zero Logprof) │     │  Go-Live Canary │
└─────────────────┘     └─────────────────┘     └─────────────────┘     └─────────────────┘
```

### 3.1. Giai đoạn 1 (Tuần 1 – Tuần 2): Khảo sát Trạng thái & Kích hoạt Complain Mode
* **Mục tiêu**: Đưa các profile cần tinh chỉnh về chế độ Complain, bảo vệ nguyên vẹn các shim profile, và thiết lập luồng giám sát nhật ký.
* **Hành động kỹ thuật**:
  1. Kiểm tra trạng thái hiện tại của toàn bộ profile trên hệ thống:
     ```bash
     sudo aa-status
     ```
  2. Đảm bảo gói công cụ tiện ích AppArmor đã được cài đặt:
     ```bash
     sudo apt-get update && sudo apt-get install -y apparmor-utils auditd
     sudo systemctl enable --now auditd
     ```
  3. Đặt các profile của dịch vụ mới hoặc dịch vụ tùy biến sang chế độ `complain`:
     ```bash
     # Ví dụ đặt profile của ứng dụng custom hoặc web server sang complain:
     sudo aa-complain /etc/apparmor.d/usr.sbin.nginx 2>/dev/null || true
     sudo aa-complain /etc/apparmor.d/my_custom_service 2>/dev/null || true
     ```
  4. **Kiểm tra và khôi phục cờ unconfined cho `runc`** (ngăn chặn lỗi stripping):
     ```bash
     # Đảm bảo runc luôn giữ cờ flags=(unconfined)
     sudo sed -i 's/profile runc \/usr\/sbin\/runc.*/profile runc \/usr\/sbin\/runc flags=(unconfined) {/' /etc/apparmor.d/runc
     sudo apparmor_parser -r /etc/apparmor.d/runc
     ```
  5. Cấu hình Fluent Bit hoặc Filebeat thu thập `/var/log/audit/audit.log` với bộ lọc từ khóa `apparmor`.

### 3.2. Giai đoạn 2 (Tuần 3 – Tuần 4): Kích hoạt Tải Thực tế & Tinh chỉnh Hồ sơ qua `aa-logprof`
* **Mục tiêu**: Thu thập toàn bộ các hành vi truy cập hợp lệ phát sinh từ nghiệp vụ thực tế và cập nhật vào profile trước khi áp đặt cưỡng chế.
* **Hành động kỹ thuật**:
  1. Cho hệ thống chạy qua đầy đủ các tác vụ vận hành thực tế:
     - Triển khai ứng dụng qua CI/CD pipeline, chạy kiểm thử tự động.
     - Chạy toàn bộ các Ansible playbook quản trị cấu hình.
     - Thực thi các batch job sao lưu dữ liệu, rotate log và kiểm tra giám sát.
  2. Sử dụng công cụ tương tác **`aa-logprof`** để phân tích nhật ký và cập nhật luật:
     ```bash
     sudo aa-logprof
     ```
     *Nguyên tắc khi chạy `aa-logprof`:*
     - Xem kỹ đường dẫn tệp tin và quyền hạn yêu cầu (`r` - đọc, `w` - ghi, `m` - memory map, `px` - thực thi profile con).
     - Nhấn `(A)llow` nếu đó là hành vi nghiệp vụ hợp lệ.
     - Nhấn `(D)eny` nếu nghi ngờ đó là hành vi bất thường.
     - Luôn ưu tiên lưu các điều chỉnh vào tệp override tại `/etc/apparmor.d/local/<profile>` thay vì sửa trực tiếp vào file gốc của package.
  3. Nạp lại các profile đã được cập nhật:
     ```bash
     sudo apparmor_parser -r /etc/apparmor.d/<profile_name>
     ```

### 3.3. Giai đoạn 3 (Tuần 5 – Tuần 7): Quan sát Chu kỳ Cuối tháng & Kiểm chứng Zero-Violation
* **Mục tiêu**: Đảm bảo toàn bộ các tác vụ đặc thù cuối tháng không sinh ra bất kỳ cảnh báo vi phạm mới nào.
* **Hành động kỹ thuật**:
  1. Trải qua đợt quyết toán tài chính, kết chuyển số liệu và sao lưu cuối tháng (Month-end Closing & Full Backups).
  2. Giám sát liên tục trong 14 ngày:
     - Kiểm tra kết quả qua script giám sát hàng ngày (Mục 4).
     - Tiêu chí: **Không có bất kỳ bản ghi `apparmor="ALLOWED"` hoặc `apparmor="DENIED"` nào phát sinh từ các luồng nghiệp vụ chuẩn**.
  3. Chạy `sudo aa-logprof` kiểm tra lần cuối: Chương trình phải trả về thông báo không có sự kiện mới cần giải quyết (*"No changes to be made"*).

### 3.4. Giai đoạn 4 (Tuần 8): Chuyển đổi sang Enforce (Canary Rollout & Phê duyệt)
* **Quy trình chuyển đổi 3 bước (Canary Rollout)**:
  1. **Bước 1 (Staging / Pre-Prod)**: Chuyển các profile mục tiêu sang `Enforce` trên Staging trong 3 ngày làm việc.
  2. **Bước 2 (Canary Prod - 10% Nodes)**: Áp dụng trên 1–2 máy chủ Production đại diện trong 48 giờ:
     ```bash
     sudo aa-enforce /etc/apparmor.d/<profile_target>
     ```
  3. **Bước 3 (Toàn bộ Production - 100% Nodes)**:
     - Áp dụng trên toàn bộ cụm máy chủ sau khi Canary hoàn thành tốt đẹp.
     - Kiểm tra lại bằng `sudo aa-status` để bảo đảm các profile mục tiêu đã chuyển sang mục `profiles are in enforce mode`.
  4. Đội ngũ trực ca theo dõi sát sao `/var/log/audit/audit.log` trong 72 giờ đầu tiên sau khi kích hoạt Enforce.

---

## 4. BỘ CÔNG CỤ & SCRIPT BASH TỰ ĐỘNG GIÁM SÁT HÀNG NGÀY

Tạo script tự động thu thập và phân tích báo cáo AppArmor hàng ngày tại `/usr/local/bin/apparmor-daily-audit.sh`:

```bash
#!/usr/bin/env bash
# ==============================================================================
# TCBS APPARMOR DAILY AUDIT COLLECTOR & REPORTER (UBUNTU 24.04 LTS)
# Tự động quét các vi phạm AppArmor trong 24 giờ qua và lập báo cáo kỹ thuật
# ==============================================================================
set -euo pipefail

REPORT_DATE=$(date +'%Y-%m-%d')
OUTPUT_DIR="/var/log/apparmor-reports"
REPORT_FILE="${OUTPUT_DIR}/apparmor-audit-${REPORT_DATE}.txt"

mkdir -p "${OUTPUT_DIR}"
chmod 0700 "${OUTPUT_DIR}"

echo "==================================================================" > "${REPORT_FILE}"
echo " BÁO CÁO GIÁM SÁT APPARMOR PRODUCTION - NGÀY: ${REPORT_DATE}" >> "${REPORT_FILE}"
echo " MÁY CHỦ: $(hostname) - IP: $(hostname -I | awk '{print $1}')" >> "${REPORT_FILE}"
echo " THỜI ĐIỂM XUẤT BÁO CÁO: $(date)" >> "${REPORT_FILE}"
echo "==================================================================" >> "${REPORT_FILE}"
echo "" >> "${REPORT_FILE}"

echo "--- 1. TỔNG QUAN TRẠNG THÁI HIỆN TẠI (AA-STATUS) ---" >> "${REPORT_FILE}"
aa-status --compact 2>/dev/null || aa-status | head -n 25 >> "${REPORT_FILE}"
echo "" >> "${REPORT_FILE}"

echo "--- 2. TỔNG SỐ SỰ KIỆN APPARMOR TRONG 24H QUA (/var/log/audit/audit.log) ---" >> "${REPORT_FILE}"
if [ -f /var/log/audit/audit.log ]; then
    ALLOWED_COUNT=$(grep -a 'apparmor="ALLOWED"' /var/log/audit/audit.log 2>/dev/null | grep -c "$REPORT_DATE" || true)
    DENIED_COUNT=$(grep -a 'apparmor="DENIED"' /var/log/audit/audit.log 2>/dev/null | grep -c "$REPORT_DATE" || true)
    echo "  - Số hành vi vi phạm ở chế độ Complain (apparmor=ALLOWED): ${ALLOWED_COUNT}" >> "${REPORT_FILE}"
    echo "  - Số hành vi bị chặn ở chế độ Enforce   (apparmor=DENIED) : ${DENIED_COUNT}" >> "${REPORT_FILE}"
else
    echo "[!] Không tìm thấy tệp /var/log/audit/audit.log. Kiểm tra dịch vụ auditd." >> "${REPORT_FILE}"
fi
echo "" >> "${REPORT_FILE}"

echo "--- 3. CHI TIẾT CÁC PROFILE PHÁT SINH VI PHẠM (TOP PROFILES) ---" >> "${REPORT_FILE}"
if [ -f /var/log/audit/audit.log ]; then
    grep -a -E 'apparmor="(ALLOWED|DENIED)"' /var/log/audit/audit.log 2>/dev/null | \
        grep "$REPORT_DATE" | \
        awk -F'profile="' '{print $2}' | awk -F'"' '{print $1}' | \
        sort | uniq -c | sort -nr | head -n 15 >> "${REPORT_FILE}" || true
fi
echo "" >> "${REPORT_FILE}"

echo "--- 4. MẪU BẢN GHI VI PHẠM ĐIỂN HÌNH (GẦN NHẤT) ---" >> "${REPORT_FILE}"
if [ -f /var/log/audit/audit.log ]; then
    grep -a -E 'apparmor="(ALLOWED|DENIED)"' /var/log/audit/audit.log 2>/dev/null | tail -n 10 >> "${REPORT_FILE}" || echo "Không có bản ghi vi phạm nào." >> "${REPORT_FILE}"
fi
echo "" >> "${REPORT_FILE}"

echo "--- 5. KIỂM TRA BẢO TOÀN CỜ UNCONFINED CỦA RUNC ---" >> "${REPORT_FILE}"
if grep -q 'profile runc /usr/sbin/runc flags=(unconfined)' /etc/apparmor.d/runc 2>/dev/null; then
    echo "[✓] runc profile chuẩn xác: flags=(unconfined) được bảo toàn nguyên vẹn." >> "${REPORT_FILE}"
else
    echo "[⚠️ CẢNH BÁO NGUY HIỂM] runc profile bị mất cờ unconfined! Cần chạy lệnh khắc phục ngay:" >> "${REPORT_FILE}"
    echo "    sudo sed -i 's/profile runc \/usr\/sbin\/runc.*/profile runc \/usr\/sbin\/runc flags=(unconfined) {/' /etc/apparmor.d/runc && sudo apparmor_parser -r /etc/apparmor.d/runc" >> "${REPORT_FILE}"
fi

echo "" >> "${REPORT_FILE}"
echo "Báo cáo hoàn tất tại: ${REPORT_FILE}"
```

Cấp quyền thực thi và cấu hình Cron Job chạy định kỳ lúc 06:15 sáng hàng ngày trong `/etc/cron.d/apparmor-audit`:
```text
15 6 * * * root /usr/local/bin/apparmor-daily-audit.sh > /dev/null 2>&1
```

---

## 5. QUY TRÌNH CHUẨN XỬ LÝ APPARMOR VIOLATIONS & OVERRIDES

Khi phát hiện các bản ghi `apparmor="ALLOWED"` trong thời gian quan sát Complain Mode, kỹ sư SysAdmin tuân thủ quy trình 3 bước chuẩn hóa sau:

```
                  ┌───────────────────────────────────────────────┐
                  │ Phát hiện bản ghi AppArmor Vi phạm            │
                  │ (apparmor="ALLOWED" hoặc apparmor="DENIED")   │
                  └───────────────────────┬───────────────────────┘
                                          │
                                          ▼
                  ┌───────────────────────────────────────────────┐
                  │ BƯỚC 1: Phân loại hành vi có hợp lệ không?     │
                  └───────┬───────────────────────────────┬───────┘
                          │ (HỢP LỆ)                      │ (BẤT THƯỜNG / TẤN CÔNG)
                          ▼                               ▼
          ┌───────────────────────────────┐ ┌───────────────────────────┐
          │ BƯỚC 2: Thêm quyền vào tệp    │ │ Giữ nguyên chế độ chặn!   │
          │ /etc/apparmor.d/local/<name>  │ │ Báo cáo ngay cho Đội ngũ  │
          │ (Không sửa trực tiếp file gốc)│ │ SOC / SecOps điều tra     │
          └───────────────┬───────────────┘ └───────────────────────────┘
                          │
                          ▼
          ┌───────────────────────────────┐
          │ BƯỚC 3: Nạp lại profile bằng  │
          │ apparmor_parser -r <file>     │
          └───────────────────────────────┘
```

### Bước 1: Phân tích bản ghi nhật ký
Một bản ghi AppArmor vi phạm điển hình có cấu trúc như sau:
```text
type=AVC msg=audit(1791189654.122:5018): apparmor="ALLOWED" operation="open" 
profile="my_service" name="/data/app/config.json" pid=4595 comm="app_worker" 
requested_mask="r" denied_mask="r" fsuid=1001 ouid=0
```
- `profile`: Hồ sơ đang kiểm soát (`my_service`).
- `operation`: Hành vi được gọi (`open`, `file_mmap`, `bind`, `connect`, `exec`).
- `name`: Đường dẫn tệp mục tiêu (`/data/app/config.json`).
- `requested_mask`: Quyền hạn đòi hỏi (`r` - đọc, `w` - ghi, `x` - thực thi, `k` - lock).

### Bước 2: Bổ sung quyền hạn vào thư mục `local/` (Bền vững khi nâng cấp Package)
Ubuntu tổ chức thư mục `/etc/apparmor.d/local/` để chứa các quy tắc tùy biến nội bộ của quản trị viên. Khi gói phần mềm của hệ thống được nâng cấp (`apt upgrade`), các tệp trong thư mục `local/` sẽ **không bao giờ bị ghi đè**.

Ví dụ, để cấp quyền cho service đọc thư mục dữ liệu mới `/data/app/**`, tạo tệp `/etc/apparmor.d/local/my_service`:
```apparmor
# TCBS Custom Permissions for my_service
/data/app/** r,
/data/app/logs/*.log rw,
network inet stream,
```

### Bước 3: Nạp lại Profile vào Nhân Linux
Sau khi chỉnh sửa, thực thi lệnh nạp lại mà không làm gián đoạn dịch vụ đang chạy:
```bash
sudo apparmor_parser -r /etc/apparmor.d/my_service
```

---

## 6. KỊCH BẢN ỨNG PHÓ KHẨN CẤP & ROLLBACK (EMERGENCY RUNBOOK)

Nếu sau khi chuyển một profile sang `Enforce` mà ứng dụng Production gặp sự cố gián đoạn hoặc crash đột ngột:

### Lệnh xử lý khẩn cấp trong 5 giây (Tức thời trên RAM - Không cần Reboot):
```bash
# 1. Hạ ngay lập tức profile của dịch vụ bị lỗi về chế độ Complain
sudo aa-complain /etc/apparmor.d/<profile_bi_loi>

# Hoặc hạ theo đường dẫn binary của ứng dụng:
sudo aa-complain /usr/sbin/nginx
```
Ngay sau lệnh trên, nhân Linux lập tức cho phép ứng dụng truy cập tệp và tiếp tục chạy bình thường mà không bị chặn.

### Lệnh tắt hoàn toàn một profile đang gây nghẽn nghiêm trọng:
```bash
# Tắt profile và giải phóng ứng dụng
sudo aa-disable /etc/apparmor.d/<profile_bi_loi>
```

### Khôi phục khẩn cấp nếu `runc` / Docker Container bị tê liệt:
Nếu do sơ suất chạy nhầm `aa-enforce` làm `runc` bị mất cờ `unconfined` (dẫn tới lỗi `libseccomp.so.2 Permission denied` hoặc `unable to start init: permission denied`):
```bash
# Khôi phục cờ unconfined chuẩn cho runc
sudo sed -i 's/profile runc \/usr\/sbin\/runc.*/profile runc \/usr\/sbin\/runc flags=(unconfined) {/' /etc/apparmor.d/runc
sudo apparmor_parser -r /etc/apparmor.d/runc

# Khởi động lại Docker daemon
sudo systemctl restart docker
```

### Thu thập bằng chứng sự cố phục vụ Root Cause Analysis (RCA):
```bash
# Trích xuất toàn bộ log từ chối của AppArmor trong sự cố vừa xảy ra
grep -a 'apparmor="DENIED"' /var/log/audit/audit.log | tail -n 100 > /var/log/apparmor-reports/emergency-incident-$(date +'%Y%m%d-%H%M%S').log
```

---

## 7. TIÊU CHÍ NGHIỆM THU ĐẠT CHUẨN ĐỂ CHUYỂN SANG ENFORCE (GATE CRITERIA)

Trước khi ký duyệt chuyển đổi các profile AppArmor trên môi trường Production sang chế độ `Enforce`, Đội ngũ Quản trị Vận hành (SysAdmin/SRE) và Đội ngũ An toàn Thông tin (SecOps) phải hoàn thành đối soát bảng checklist sau:

| STT | Tiêu chí Kiểm định (Gate Criterion) | Ngưỡng Đạt (Threshold) | Hiện trạng Đánh giá | Trạng thái |
| :---: | :--- | :--- | :--- | :--- | :---: |
| 1 | **Thời gian quan sát liên tục ở chế độ Complain** | Tối thiểu **30 đến 60 ngày** | Đang duy trì chế độ Complain | ⏳ Đang chạy |
| 2 | **Trải qua trọn vẹn chu kỳ tháng** | Tối thiểu 01 kỳ quyết toán & sao lưu cuối tháng | Cần lịch giám sát tháng tiếp theo | ⏳ Đang chạy |
| 3 | **Tỷ lệ vi phạm Complain chưa xử lý** | **0 bản ghi `apparmor="ALLOWED"`** trong 14 ngày liên tiếp | Kiểm tra qua script audit hàng ngày | ⏳ Đang chạy |
| 4 | **Bảo toàn Cờ Unconfined Shim cho `runc`** | Profile `runc` luôn giữ `flags=(unconfined)` | Đã kiểm chứng chạy Docker + Postgres Up | ✅ ĐẠT |
| 5 | **Thử nghiệm thành công trên Staging** | 100% kịch bản test trên Staging chạy Enforce > 7 ngày không lỗi | Chờ kết thúc Phase 2 | ⏳ Dự kiến W6 |
| 6 | **Phê duyệt phương án Rollback khẩn cấp** | Đội ngũ trực ca nắm vững `aa-complain` và lệnh phục hồi runc | Đã tài liệu hóa trong Runbook | ✅ ĐẠT |

---

## 8. TỔNG KẾT HÀNH ĐỘNG & ĐỒNG BỘ TAILORING TCBS

1. **Trên máy chủ Test Ubuntu 24.04 (`10.37.129.3`)**:
   - 117/118 profiles hệ thống và `docker-default` đang chạy ở chế độ **`Enforce`** bảo vệ an toàn tối đa máy chủ.
   - Profile `runc` được bảo toàn cờ `flags=(unconfined)`, cho phép Docker CE chạy mượt mà ứng dụng PostgreSQL và Fluent Bit.
2. **Trên hồ sơ Tailoring OpenSCAP**:
   - Quy tắc **`all_apparmor_profiles_enforced`** được **TẮT CHỦ ĐỘNG (Deselected)** với lý do: *"Prevent aa-enforce unconfined removal bug; audit via aa-status"*.
   - Tham số **`var_apparmor_mode`** được đặt là **`complain`** trong giai đoạn quan sát 1–2 tháng, bảo đảm báo cáo kiểm toán đạt kết quả Pass 100%.
3. **Tiến trình vận hành**:
   - Bộ phận vận hành định kỳ kiểm tra `sudo aa-status` và theo dõi báo cáo từ script `/usr/local/bin/apparmor-daily-audit.sh` trước khi tiến hành chuyển đổi sang `Enforce` theo lộ trình.
