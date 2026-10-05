# KẾ HOẠCH TOÀN DIỆN: GIÁM SÁT VÀ CHUYỂN ĐỔI SELINUX TỪ PERMISSIVE SANG ENFORCING
## LỘ TRÌNH QUAN SÁT 1–2 THÁNG TRÊN MÔI TRƯỜNG PRODUCTION (TCBS STANDARDS)

> **Tài liệu tham chiếu:** 
> - Chuẩn an toàn thông tin TCVN 14423:2026 (Cấp độ 3 & 4)
> - CIS Red Hat Enterprise Linux 9 Benchmark Level 2 Server
> - Báo cáo tác động vận hành: [BAO_CAO_CHI_TIET_TAC_DONG_VAN_HANH_SYSADMIN.md](file:///Users/cmdx/work/tcbs/TCVN/BAO_CAO_CHI_TIET_TAC_DONG_VAN_HANH_SYSADMIN.md)

---

## 1. MỤC TIÊU & NGUYÊN TẮC CỐT LÕI

SELinux (Security-Enhanced Linux) là cơ chế kiểm soát truy cập bắt buộc (Mandatory Access Control - MAC) ở tầng nhân Linux. Khi bật ở chế độ `Enforcing`, SELinux sẽ chặn đứng mọi hành vi vi phạm chính sách bảo mật, ngay cả khi hành vi đó được thực hiện bởi tài khoản `root`.

Tuy nhiên, đối với một hạ tầng Production chưa từng triển khai SELinux, việc bật ngay chế độ `Enforcing` tiềm ẩn rủi ro rất cao làm gãy vỡ dịch vụ (Downtime), ngắt kết nối database, gián đoạn container, và lỗi các script tự động hóa.

### Nguyên tắc triển khai:
1. **Zero-Downtime / Zero-Disruption**: Không để bất kỳ nghiệp vụ kinh doanh nào bị gián đoạn do SELinux.
2. **Permissive Observation Window (1–2 tháng)**: Duy trì máy chủ ở chế độ `SELINUX=permissive`. Ở chế độ này, nhân Linux **vẫn nạp chính sách và kiểm tra 100% quyền truy cập**, ghi nhật ký mọi hành vi vi phạm vào `/var/log/audit/audit.log` (dưới dạng các bản ghi `type=AVC`), nhưng **KHÔNG CHẶN** tiến trình.
3. **Phủ kín toàn bộ chu kỳ nghiệp vụ**: Thời gian 1–2 tháng là bắt buộc để hệ thống trải qua:
   - Toàn bộ chu kỳ chốt phiên giao dịch, quyết toán cuối ngày (Daily Batch Jobs).
   - Chu kỳ sao lưu dữ liệu, bảo trì cuối tuần (Weekly Full Backups).
   - Chu kỳ báo cáo tài chính, quyết toán cuối tháng (Month-end Closing Jobs).
   - Các kịch bản diễn tập khôi phục thảm họa (Disaster Recovery Failover).
4. **Data-Driven Cutover**: Chỉ chuyển đổi sang `Enforcing` khi hệ thống đạt chỉ số **Zero Unhandled AVC Denials** trong tối thiểu 14 ngày liên tục.

---

## 2. KIẾN TRÚC THU THẬP & PHÂN TÍCH NHẬT KÝ SELINUX

```
┌────────────────────────────────────────────────────────────────────────┐
│ LINUX KERNEL (SELINUX SUBSYSTEM)                                       │
│                                                                        │
│  Target Process (nginx, postgres, docker, backup_script)               │
│       │                                                                │
│       ▼                                                                │
│  [SELinux Access Vector Cache (AVC) Check]                             │
│       │                                                                │
│       ├─► (Quyền Hợp lệ) ────────► Cho phép thực thi                   │
│       │                                                                │
│       └─► (Quyền Bị từ chối)                                           │
│                 │                                                      │
│                 ▼                                                      │
│         [SELINUX=permissive]                                           │
│                 │                                                      │
│                 ├─► Cho phép tiến trình tiếp tục (Không crash)        │
│                 │                                                      │
│                 └─► Ghi bản ghi AVC Denial vào kernel audit buffer     │
└─────────────────┬──────────────────────────────────────────────────────┘
                  │
                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│ AUDITD DAEMON & LOCAL LOG ANALYSIS                                     │
│                                                                        │
│  Tệp nhật ký: /var/log/audit/audit.log                                 │
│  Công cụ phân tích:                                                    │
│    - ausearch -m avc -ts recent                                        │
│    - aureport -a                                                       │
│    - sealert -a /var/log/audit/audit.log                               │
│    - audit2allow -w -a                                                 │
└─────────────────┬──────────────────────────────────────────────────────┘
                  │ (Filebeat / Vector)
                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│ CENTRALIZED SIEM & NOTIFICATION (ELASTICSEARCH / SPLUNK)               │
│                                                                        │
│  - Dashboard: "SELinux Production AVC Denials Overview"                 │
│  - Alerting: Kênh Slack / Telegram / PagerDuty khi có Denial mới       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. LỘ TRÌNH 4 GIAI ĐOẠN TỪ PERMISSIVE ĐẾN ENFORCING

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   GIAI ĐOẠN 1   │     │   GIAI ĐOẠN 2   │     │   GIAI ĐOẠN 3   │     │   GIAI ĐOẠN 4   │
│  (Tuần 1 - 2)   │────►│  (Tuần 3 - 4)   │────►│  (Tuần 5 - 7)   │────►│    (Tuần 8)     │
│  Thiết lập nạp  │     │  Vận hành tải   │     │  Quan sát chu   │     │   Chuyển đổi    │
│  Permissive &   │     │  thực tế & Xây  │     │  kỳ cuối tháng  │     │   Enforcing &   │
│  Công cụ đo đạc │     │  dựng Module    │     │  (Zero Denial)  │     │  Go-Live chính  │
└─────────────────┘     └─────────────────┘     └─────────────────┘     └─────────────────┘
```

### 3.1. Giai đoạn 1 (Tuần 1 – Tuần 2): Thiết lập Permissive & Công cụ Phân tích
* **Hành động kỹ thuật**:
  1. Kiểm tra trạng thái và nạp chế độ `permissive`:
     ```bash
     sudo setenforce 0
     sudo sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config
     ```
  2. Cài đặt bộ công cụ chẩn đoán và phân tích SELinux:
     ```bash
     sudo dnf install -y setroubleshoot-server policycoreutils-python-utils audit
     sudo systemctl enable --now auditd
     ```
  3. Cấu hình gửi cảnh báo AVC Denials về SIEM / Filebeat:
     - Bổ sung bộ lọc trong Filebeat/Vector để bắt các dòng log có `type=AVC` hoặc `type=USER_AVC`.
  4. Triển khai script quét và báo cáo tự động hàng ngày (xem mục 4).

### 3.2. Giai đoạn 2 (Tuần 3 – Tuần 4): Kích hoạt Tải Thực tế & Xây dựng Policy Modules
* **Hành động kỹ thuật**:
  1. Thực hiện đầy đủ các quy trình vận hành thực tế:
     - Chạy toàn bộ các Ansible Playbook bảo trì định kỳ.
     - Triển khai các bản release ứng dụng qua CI/CD pipeline.
     - Chạy sao lưu Database (PostgreSQL dump, MySQL dump, Redis RDB save).
     - Nâng cấp kernel và bản vá bảo mật hệ thống.
  2. Đọc và phân tích thông báo từ chối quyền:
     ```bash
     # Liệt kê tóm tắt các vi phạm
     sudo aureport -a
     
     # Phân tích nguyên nhân và giải pháp đề xuất bằng tiếng người
     sudo sealert -a /var/log/audit/audit.log
     
     # Xem giải thích chi tiết từ chối dạng rule SELinux
     sudo ausearch -m avc -ts recent | audit2allow -w
     ```
  3. Áp dụng quy tắc xử lý theo thứ tự ưu tiên (Xem chi tiết tại Mục 5):
     - *Ưu tiên 1*: Gán nhãn tệp đúng chuẩn (`semanage fcontext` + `restorecon`).
     - *Ưu tiên 2*: Bật cờ Boolean có sẵn của hệ điều hành (`setsebool -P`).
     - *Ưu tiên 3*: Tạo Custom SELinux Policy Module (`audit2allow -M`).

### 3.3. Giai đoạn 3 (Tuần 5 – Tuần 7): Quan sát Chu kỳ Cuối tháng & Kiểm chứng Zero-Denial
* **Hành động kỹ thuật**:
  1. Trải qua đợt cao điểm giao dịch và quyết toán tài chính cuối tháng (Month-end Batch Processing).
  2. Đánh giá nhật ký AVC liên tục trong 14 ngày sau khi đã nạp toàn bộ Custom Policy Modules:
     - Tiêu chí: **Không xuất hiện thêm bất kỳ bản ghi AVC Denial nào mới đối với các luồng nghiệp vụ hợp lệ**.
  3. Kiểm tra tính toàn vẹn của hệ thống:
     - Không có tiến trình nào bị gán nhãn sai (`unconfined_service_t` bừa bãi).
     - Không có tệp cấu hình nào bị mất nhãn sau khi reboot.

### 3.4. Giai đoạn 4 (Tuần 8): Chuyển đổi sang Enforcing (Go-Live & Phê duyệt)
* **Quy trình chuyển đổi 3 bước (Canary Rollout)**:
  1. **Bước 1 (Staging / Pre-Prod)**: Chuyển toàn bộ máy chủ Staging sang `Enforcing` trong 3 ngày làm việc.
  2. **Bước 2 (Canary Prod - 10% Nodes)**: Chuyển 1-2 máy chủ ứng dụng đại diện sang `Enforcing` trong 48 giờ.
  3. **Bước 3 (Toàn bộ Prod - 100% Nodes)**:
     ```bash
     # Bật tạm thời trong phiên làm việc
     sudo setenforce 1
     
     # Lưu vĩnh viễn cấu hình cho các lần reboot tiếp theo
     sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
     ```
  4. Đội ngũ trực ca giám sát liên tục trong 72 giờ đầu sau khi bật `Enforcing`.

---

## 4. BỘ CÔNG CỤ & SCRIPT BASH TỰ ĐỘNG GIÁM SÁT HÀNG NGÀY

Tạo script thu thập và phân tích báo cáo AVC hàng ngày tại `/usr/local/bin/selinux-daily-audit.sh`:

```bash
#!/usr/bin/env bash
# ==============================================================================
# TCBS SELINUX DAILY AUDIT COLLECTOR & REPORTER
# Tự động quét các vi phạm AVC trong 24 giờ qua và gửi báo cáo về SecOps/DevOps
# ==============================================================================
set -euo pipefail

REPORT_DATE=$(date +'%Y-%m-%d')
OUTPUT_DIR="/var/log/selinux-reports"
REPORT_FILE="${OUTPUT_DIR}/selinux-audit-${REPORT_DATE}.txt"

mkdir -p "${OUTPUT_DIR}"
chmod 0700 "${OUTPUT_DIR}"

echo "==================================================================" > "${REPORT_FILE}"
echo " BÁO CÁO GIÁM SÁT SELINUX PRODUCTION - NGÀY: ${REPORT_DATE}" >> "${REPORT_FILE}"
echo " MÁY CHỦ: $(hostname) - IP: $(hostname -I | awk '{print $1}')" >> "${REPORT_FILE}"
echo " CHẾ ĐỘ SELINUX HIỆN TẠI: $(getenforce)" >> "${REPORT_FILE}"
echo "==================================================================" >> "${REPORT_FILE}"
echo "" >> "${REPORT_FILE}"

echo "--- 1. TỔNG SỐ SỰ KIỆN AVC DENIALS THEO AUREPORT ---" >> "${REPORT_FILE}"
aureport -a -ts yesterday >> "${REPORT_FILE}" || true
echo "" >> "${REPORT_FILE}"

echo "--- 2. CHI TIẾT CÁC TIẾN TRÌNH VÀ CONTEXT BỊ TỪ CHỐI (AUSEARCH) ---" >> "${REPORT_FILE}"
ausearch -m avc,user_avc -ts yesterday -i >> "${REPORT_FILE}" 2>/dev/null || echo "Không có sự kiện AVC nào trong 24h qua." >> "${REPORT_FILE}"
echo "" >> "${REPORT_FILE}"

echo "--- 3. ĐỀ XUẤT CHÍNH SÁCH TỪ AUDIT2ALLOW (NẾU CÓ) ---" >> "${REPORT_FILE}"
if ausearch -m avc,user_avc -ts yesterday 2>/dev/null | grep -q 'type=AVC'; then
    echo "[!] Phát hiện sự kiện từ chối quyền. Dưới đây là gợi ý từ audit2allow:" >> "${REPORT_FILE}"
    ausearch -m avc,user_avc -ts yesterday 2>/dev/null | audit2allow -w >> "${REPORT_FILE}"
    echo "" >> "${REPORT_FILE}"
    echo "--- Gợi ý mã chính sách mẫu (audit2allow -a): ---" >> "${REPORT_FILE}"
    ausearch -m avc,user_avc -ts yesterday 2>/dev/null | audit2allow -a >> "${REPORT_FILE}"
else
    echo "[✓] Hệ thống hoàn toàn sạch, không có bất kỳ AVC Denial nào!" >> "${REPORT_FILE}"
fi

echo "" >> "${REPORT_FILE}"
echo "Báo cáo hoàn tất tại: ${REPORT_FILE}"
```

Cấu hình Cron Job chạy vào lúc 06:00 sáng hàng ngày trong `/etc/cron.d/selinux-audit`:
```text
0 6 * * * root /usr/local/bin/selinux-daily-audit.sh > /dev/null 2>&1
```

---

## 5. QUY TRÌNH CHUẨN XỬ LÝ AVC DENIALS (3 BƯỚC)

Khi phát hiện một bản ghi AVC Denial trong báo cáo, SysAdmin **TUYỆT ĐỐI KHÔNG ĐƯỢC CHẠY NGAY `audit2allow -M`**, vì điều đó có thể vô tình mở toang quyền cho một tiến trình độc hại hoặc che giấu lỗi cấu hình sai đường dẫn. Hãy tuân thủ nghiêm ngặt 3 bước sau:

```
                  ┌───────────────────────────────┐
                  │ Phát hiện bản ghi AVC Denial  │
                  └──────────────┬────────────────┘
                                 │
                                 ▼
         ┌─────────────────────────────────────────────────┐
         │ BƯỚC 1: Có phải do thư mục/tệp bị gắn sai nhãn? │
         └───────┬─────────────────────────────────┬───────┘
                 │ (ĐÚNG)                          │ (SAI)
                 ▼                                 ▼
   ┌───────────────────────────────┐   ┌──────────────────────────────┐
   │ Chạy semanage fcontext        │   │ BƯỚC 2: Có SELinux Boolean   │
   │ và restorecon -Rv             │   │ hỗ trợ tính năng này không?  │
   └───────────────────────────────┘   └───────┬──────────────┬───────┘
                                               │ (CÓ)         │ (KHÔNG)
                                               ▼              ▼
                               ┌─────────────────────────┐  ┌─────────────────────────┐
                               │ Bật boolean bằng:       │  │ BƯỚC 3: Tạo Custom      │
                               │ setsebool -P <flag> on  │  │ Policy Module riêng     │
                               └─────────────────────────┘  │ qua audit2allow -M      │
                                                            └─────────────────────────┘
```

### Bước 1: Khắc phục lỗi sai nhãn tệp (File Context Mismatch)
* **Dấu hiệu**: Đổi đường dẫn lưu trữ data (ví dụ PostgreSQL sang `/data/pg_data`, Nginx root sang `/var/www/my-app`, Docker storage sang `/data/docker`).
* **Lỗi**: Tiến trình `postgresql_t` hoặc `httpd_t` bị từ chối đọc tệp có nhãn `default_t` hoặc `var_t`.
* **Cách khắc phục**:
  ```bash
  # Gán nhãn chuẩn vĩnh viễn vào cơ sở dữ liệu chính sách SELinux
  sudo semanage fcontext -a -t postgresql_db_t "/data/pg_data(/.*)?"
  
  # Quét và áp dụng nhãn lại cho toàn bộ thư mục và tệp con
  sudo restorecon -Rv /data/pg_data
  ```

### Bước 2: Kích hoạt SELinux Booleans có sẵn
* **Dấu hiệu**: Ứng dụng muốn thực hiện hành vi mạng hoặc giao tiếp tiêu chuẩn nhưng SELinux mặc định tắt tính năng đó (ví dụ: Nginx muốn kết nối ra backend qua mạng socket, hoặc máy chủ chia sẻ thư mục qua NFS/Samba).
* **Tra cứu cờ boolean**:
  ```bash
  # Tìm các boolean liên quan đến dịch vụ (ví dụ httpd / web)
  getsebool -a | grep httpd
  ```
* **Kích hoạt cờ vĩnh viễn (`-P`)**:
  ```bash
  # Cho phép Web server kết nối ra các dịch vụ mạng khác (Reverse Proxy)
  sudo setsebool -P httpd_can_network_connect on
  
  # Cho phép Web server kết nối tới database
  sudo setsebool -P httpd_can_network_connect_db on
  
  # Cho phép tiến trình chạy dưới user kết nối mạng nếu cần
  sudo setsebool -P selinuxuser_tcp_server on
  ```

### Bước 3: Tạo Custom Policy Module (Khi không có Boolean tương thích)
Chỉ áp dụng cho các ứng dụng viết riêng (in-house services), phần mềm của bên thứ 3 cài đặt dạng binary độc lập (Cortex XDR, Filebeat, Custom Exporter) mà policy gốc của RHEL chưa có định nghĩa:

```bash
# 1. Trích xuất bản ghi AVC của riêng tiến trình mục tiêu
ausearch -m avc -c "my_app_service" -ts recent > /tmp/myapp_avc.log

# 2. Xem phân tích của audit2allow để hiểu rõ quyền gì sắp được cấp
audit2allow -i /tmp/myapp_avc.log -r

# 3. Tạo module chính sách (sinh ra 2 tệp: myapp_custom.te và myapp_custom.pp)
checkmodule -M -m -o /tmp/myapp_custom.mod /tmp/myapp_custom.te
semodule_package -o /tmp/myapp_custom.pp -m /tmp/myapp_custom.mod
# (Hoặc cú pháp nhanh):
audit2allow -i /tmp/myapp_avc.log -M myapp_custom

# 4. Kiểm tra mã nguồn tệp TE (.te) trước khi nạp để bảo đảm không cấp quyền nguy hiểm
cat myapp_custom.te

# 5. Cài đặt module vào nhân Linux
sudo semodule -i myapp_custom.pp

# 6. Kiểm tra lại danh sách các custom modules đang hoạt động
sudo semodule -l | grep myapp_custom
```

---

## 6. KỊCH BẢN ỨNG PHÓ KHẨN CẤP & ROLLBACK (EMERGENCY RUNBOOK)

Nếu sau khi chuyển sang `SELINUX=enforcing` mà xảy ra sự cố gián đoạn dịch vụ nghiêm trọng trên Production:

### Lệnh xử lý khẩn cấp 10 giây (Tức thời trên RAM):
```bash
# Lập tức hạ SELinux về Permissive (Không cần reboot máy)
sudo setenforce 0

# Xác nhận lại trạng thái
getenforce
# Kết quả phải trả về: Permissive
```
Ngay sau lệnh trên, mọi thao tác bị chặn sẽ được kernel cho phép thực thi bình thường trở lại ngay lập tức.

### Khắc phục cấu hình khởi động (Persistent):
```bash
sudo sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
```

### Thu thập bằng chứng sự cố:
```bash
# Trích xuất toàn bộ lỗi phát sinh trong thời gian bật Enforcing vừa qua
ausearch -m avc -ts recent > /var/log/selinux-reports/emergency-incident-$(date +'%Y%m%d-%H%M%S').log
```

---

## 7. TIÊU CHÍ NGHIỆM THU ĐẠT CHUẨN ĐỂ CHUYỂN SANG ENFORCING (GATE CRITERIA)

Trước khi ký duyệt biên bản chuyển đổi toàn bộ máy chủ Production sang `SELINUX=enforcing`, Đội ngũ Quản trị Vận hành và Đội ngũ An toàn Thông tin phải hoàn thành đối soát bảng checklist sau:

| STT | Tiêu chí Kiểm định (Gate Criterion) | Ngưỡng Đạt (Threshold) | Hiện trạng Đánh giá | Trạng thái |
| :---: | :--- | :--- | :--- | :---: |
| 1 | **Thời gian quan sát liên tục ở chế độ Permissive** | Tối thiểu **30 đến 60 ngày** | Đã cấu hình nạp `permissive` | ⏳ Đang chạy |
| 2 | **Trải qua trọn vẹn chu kỳ tháng** | Tối thiểu 01 kỳ quyết toán & sao lưu cuối tháng | Cần lịch giám sát tháng tiếp theo | ⏳ Đang chạy |
| 3 | **Tỷ lệ AVC Denials chưa xử lý (Unhandled AVC)** | **0 bản ghi** trong 14 ngày liên tiếp | Kiểm tra qua `aureport -a` | ⏳ Đang chạy |
| 4 | **Hoàn thành Custom Modules cho các App đặc thù** | 100% dịch vụ (Docker, PG, Redis, XDR, Filebeat) có label chuẩn | Đã chuẩn bị mẫu lệnh semanage | ⏳ Đang chạy |
| 5 | **Thử nghiệm thành công trên môi trường Staging** | 100% kịch bản test trên Staging chạy ở chế độ Enforcing > 7 ngày | Chờ kết thúc Phase 2 | ⏳ Dự kiến W6 |
| 6 | **Phê duyệt phương án Rollback khẩn cấp** | Đội ngũ trực ca nắm vững lệnh `setenforce 0` và tệp cứu hộ | Đã tài liệu hóa trong Runbook | ✅ ĐẠT |

---

## 8. TỔNG KẾT HÀNH ĐỘNG TIẾP THEO

1. **Trên máy chủ Test (10.37.129.4 RHEL 9)**: 
   - Đã chuyển đổi thành công sang `SELINUX=permissive` cả trên RAM và tệp cấu hình `/etc/selinux/config`.
   - Kết quả kiểm định với OpenSCAP Tailoring profile trả về: `Result pass`.
2. **Trên hồ sơ OpenSCAP Tailoring**: 
   - Tham số `var_selinux_state` được gán chính thức giá trị `permissive` trong suốt giai đoạn quan sát 1–2 tháng, bảo đảm báo cáo tuân thủ đánh giá Pass hợp lệ.
3. **Tiến trình theo dõi**: 
   - Bộ phận vận hành bắt đầu kích hoạt thu thập log định kỳ và phân loại nhãn ngữ cảnh (context) trước khi tiến hành chuyển đổi sang `enforcing` theo đúng lộ trình đã đề ra.
