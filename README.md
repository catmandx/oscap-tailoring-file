# TCBS OpenSCAP Tailoring Files (TCVN 14423:2026 & CIS Level 2 Server)

Bộ hồ sơ tinh chỉnh OpenSCAP Tailoring Files tuân thủ **Tiêu chuẩn Quốc gia TCVN 14423:2026** (Cấp độ 3 và Cấp độ 4) kế thừa từ hồ sơ chuẩn **CIS Benchmark Level 2 - Server** cho 04 hệ điều hành:

1. **Amazon Linux 2023** (`ssg-al2023-ds-tailoring.xml`)
2. **Ubuntu Linux 24.04 LTS** (`ssg-ubuntu2404-ds-tailoring.xml`)
3. **Red Hat Enterprise Linux 8** (`ssg-rhel8-ds-tailoring.xml`)
4. **Red Hat Enterprise Linux 9** (`ssg-rhel9-ds-tailoring.xml`)

---

## 1. Biện pháp Kiểm soát Bù trừ Tích hợp (Compensating Controls)

Các quy tắc được tinh chỉnh tắt (`selected="false"`) trong các tệp này dựa trên 5 Trụ cột an ninh mạng thực tế của tổ chức:
- **Palo Alto Networks Cortex XDR**: Giám sát điểm cuối, FIM thời gian thực, Process Telemetry -> Thay thế AIDE.
- **Mã hóa Hạ tầng 100% (Encryption at Rest)**: 100% AWS EBS & RDS Encryption qua KMS AES-256, VMware VM/vSAN Encryption -> Thay thế LUKS `encrypt_partitions`.
- **Lưu trữ Nhật ký Bất biến**: Streaming log ra Amazon S3 Object Lock (Compliance Mode / WORM 01 năm) & SIEM SOC 24/7 + LVM auto-expand -> Thay thế chia nhỏ phân vùng ổ đĩa cục bộ.
- **Kiến trúc Mạng Đa lớp**: Phân vùng VPC -> Subnets, Security Groups (Default-Deny), AWS Network Firewall (Inbound & Outbound NFW) -> Thay thế tường lửa host (`firewalld`, `nftables`, `ufw`).
- **CyberArk PAM & Chính sách Mật khẩu Dự phòng (TCVN 14423:2026 Mục 6.6.2.2)**: CyberArk PAM quản lý mật khẩu tập trung (Vaulting, OTP xoay vòng, MFA 2FA, Session Recording), cấp quyền `NOPASSWD sudo` cho user admin được PAM quản lý, khóa trực tiếp password của `root` (bỏ qua `ensure_root_password_configured` vì phục hồi qua Cloud Console/IAM/Snapshot). Đối với các quy tắc chính sách mật khẩu theo TCVN 6.6.2.2 (độ dài tối thiểu 14 ký tự, 4 nhóm ký tự, chu kỳ đổi 60 ngày - 01 lần/02 tháng, nhớ 10 mật khẩu cũ): **Bật trở lại trên OS làm cơ chế dự phòng an toàn (CyberArk PAM already manages these settings, but enable as a failsafe in case PAM doesn't enforce the policy)**. Chỉ tắt chủ động cơ chế khóa tài khoản cục bộ `accounts_passwords_pam_faillock_*` để tránh nguy cơ khóa cứng các tài khoản dịch vụ và automation/CI-CD.
- **Auditd & Log Shipping Tập trung**: Vô hiệu hóa toàn bộ các rule bắt syscalls sửa/xóa/mở file thông thường; giữ lại 5 nhóm sự kiện kiểm toán lõi kết hợp Cortex XDR. Bỏ qua `package_systemd-journal-remote_installed` vì tổ chức sử dụng **Elastic Filebeat** / Vector để stream log lên S3 & SIEM.
- **Loại bỏ Local Mail Transfer Agent**: Bỏ qua `package_postfix_installed` và các cấu hình Postfix cục bộ vì máy chủ nghiệp vụ không có nhu cầu gửi/nhận email nội bộ (toàn bộ cảnh báo chuyển tiếp qua SIEM / APM / Webhook tập trung).
- **Hỗ trợ Container Networking (`net.ipv4.ip_forward = 0`)**: Bỏ qua quy tắc chặn IP forwarding để Docker và Kubernetes CNI bridge routing hoạt động bình thường mà không bị rớt mạng. Kiểm soát an toàn tại tầng mạng thông qua AWS Network Firewall & Security Groups.
- **Khơi thông Tự động hóa Ansible & CI/CD (`sudo_add_use_pty`)**: Bỏ qua quy tắc bắt buộc PTY để các công cụ tự động hóa không tương tác (Ansible pipelining, Jenkins/GitLab runners, cron batch jobs) thực thi sudo thông suốt. Bù trừ bằng CyberArk PAM full session video recording và `/var/log/sudo.log`.
- **Hỗ trợ Multi-NIC, VPN & K8s CNI Overlay (`rp_filter = 1`)**: Bỏ qua kiểm tra Strict Reverse Path Filtering để tránh rớt gói tin định tuyến không đối xứng (asymmetric routing). Kiểm soát bằng cơ chế chống giả mạo IP nguồn (Anti-spoofing) tại tầng hypervisor của AWS VPC.
- **Chế độ SELinux Permissive (Giai đoạn Quan sát 1–2 tháng)**: Gán giá trị biến `var_selinux_state = permissive` trong hồ sơ Tailoring để nhân Linux ghi nhận toàn bộ vi phạm AVC Denials vào `/var/log/audit/audit.log` mà không làm crash ứng dụng Production; phục vụ hoàn thiện Custom Policy Modules trước khi chuyển sang `enforcing`. Chi tiết: [Kế hoạch Giám sát SELinux](file:///Users/cmdx/work/tcbs/TCVN/KE_HOACH_GIAM_SAT_SELINUX_PERMISSIVE_DEN_ENFORCING.md).
- **Bảo toàn Cờ Unconfined Shim của AppArmor (`all_apparmor_profiles_enforced`)**: Bỏ qua quy tắc cưỡng chế toàn bộ profile trên Ubuntu 24.04 để ngăn ngừa lỗi công cụ `aa-enforce` tự ý xóa bỏ cờ `flags=(unconfined)` trong các shim profile của hệ điều hành (làm tê liệt `runc` và container engines). 117/118 profiles hệ thống và `docker-default` vẫn được Enforce đầy đủ; quy trình kiểm toán chuyển sang chạy `aa-status` thủ công định kỳ. Chi tiết: [Kế hoạch Giám sát AppArmor](file:///Users/cmdx/work/tcbs/oscap-tailoring-file/docs/KE_HOACH_GIAM_SAT_APPARMOR_COMPLAIN_DEN_ENFORCE.md).
- **Hỗ trợ Storage Driver Container OverlayFS (`kernel_module_overlayfs_disabled`)**: Bỏ qua quy tắc vô hiệu hóa kernel module `overlay` trên Ubuntu 24.04 và RHEL 8. Đây là điều kiện tiên quyết bắt buộc để Docker Engine và Kubernetes containerd khởi tạo `overlay2` storage driver cho mọi container image và layer filesystem.
- **Bảo toàn Công cụ Debug Mạng Telnet Client (`package_telnet_removed` / `package_inetutils-telnet_removed`)**: Bỏ qua quy tắc gỡ bỏ telnet client trên cả 4 OS. Lệnh `telnet` client là công cụ chẩn đoán mạng thiết yếu để SysAdmin / DevOps kiểm tra độ thông tuyến TCP port (`telnet <host> <port>`) tới database, microservices và API bên thứ ba. Quy tắc gỡ bỏ dịch vụ máy chủ telnet daemon không mã hóa (`package_telnet-server_removed` / `package_telnetd_removed`) vẫn được DUY TRÌ BẬT 100%.
- **Tùy biến Banner Cảnh báo Pháp lý & Nhận diện Tài sản TCBS / TCEX**: Tùy biến toàn bộ các biến banner (`login_banner_*`, `remote_login_banner_*`, `motd_banner_*`, `cis_banner_text`, `dconf_login_banner_*`) sang thông điệp chuẩn của tổ chức: *"TCBS / TCEX - CANH BAO: He thong thong tin nay la tai san cua TCBS va TCEX. Khong phan su mien truy cap va su dung. Moi hoat dong tren he thong deu duoc giam sat, ghi nhat ky va bao cao theo quy dinh an toan thong tin. Moi hanh vi vi pham se bi truy cuu trach nhiem phap ly. Authorized users only. Unauthorized access is prohibited. All activity may be monitored and reported."* Biểu thức chính quy (regex) tương ứng được thiết lập linh hoạt để kiểm toán đạt 100% tuân thủ.

---

## 2. Hướng dẫn Lệnh Quét Đánh giá (Usage Commands)

### A. Amazon Linux 2023 (AL2023)
```bash
oscap xccdf eval \
  --tailoring-file ssg-al2023-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_al2023_cis_l2_tcvn14423 \
  --oval-results \
  --results /tmp/xccdf-results-al2023.xml \
  --results-arf /tmp/arf-al2023.xml \
  --report /tmp/report-al2023.html \
  ssg-al2023-ds.xml
```

### B. Ubuntu Linux 24.04 LTS (Noble Numbat)
```bash
oscap xccdf eval \
  --tailoring-file ssg-ubuntu2404-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_ubuntu2404_cis_l2_tcvn14423 \
  --oval-results \
  --results /tmp/xccdf-results-ubuntu2404.xml \
  --results-arf /tmp/arf-ubuntu2404.xml \
  --report /tmp/report-ubuntu2404.html \
  ssg-ubuntu2404-ds.xml
```

### C. Red Hat Enterprise Linux 8 (RHEL 8)
```bash
oscap xccdf eval \
  --tailoring-file ssg-rhel8-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_rhel8_cis_l2_tcvn14423 \
  --oval-results \
  --results /tmp/xccdf-results-rhel8.xml \
  --results-arf /tmp/arf-rhel8.xml \
  --report /tmp/report-rhel8.html \
  ssg-rhel8-ds.xml
```

### D. Red Hat Enterprise Linux 9 (RHEL 9)
```bash
oscap xccdf eval \
  --tailoring-file ssg-rhel9-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_rhel9_cis_l2_tcvn14423 \
  --oval-results \
  --results /tmp/xccdf-results-rhel9.xml \
  --results-arf /tmp/arf-rhel9.xml \
  --report /tmp/report-rhel9.html \
  ssg-rhel9-ds.xml
```

---

## 3. Hướng dẫn Lệnh Tự động Khắc phục (Auto Remediation Commands)

Khi hệ thống phát hiện các điểm chưa đạt chuẩn tuân thủ, OpenSCAP cung cấp khả năng tự động khắc phục (Remediation). 

> [!NOTE]
> **Cơ chế mặc định của OpenSCAP**:
> - Khi thực hiện remediation (dù chạy trực tiếp `--remediate` hay qua file `results.xml`), OpenSCAP **CHỈ thực thi kịch bản sửa lỗi cho các quy tắc bị `fail`**. Các quy tắc đã `pass`, `notapplicable` hoặc được tắt (`selected="false"` trong Tailoring file) **sẽ KHÔNG bị can thiệp**.
> - Nhờ sử dụng **Tailoring File**, toàn bộ các rủi ro vận hành (như xóa cờ unconfined của AppArmor, chặn IP Forwarding của Docker/K8s, khóa tài khoản tự động faillock) đều **được loại trừ 100%**.

Dưới đây là 3 phương thức thực hiện Remediation tùy theo kịch bản vận hành:

---

### 3.1. Phương thức 1: Quét và Tự động Khắc phục Trực tiếp (`--remediate`)
*Cơ chế:* Bộ máy quét sẽ kiểm tra từng quy tắc. Nếu quy tắc **`fail`**, nó sẽ chạy ngay kịch bản fix cho quy tắc đó; nếu **`pass`**, nó sẽ bỏ qua.

#### A. Amazon Linux 2023 (AL2023)
```bash
oscap xccdf eval \
  --remediate \
  --tailoring-file ssg-al2023-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_al2023_cis_l2_tcvn14423 \
  --oval-results \
  --results /tmp/xccdf-results-al2023-remediated.xml \
  --results-arf /tmp/arf-al2023-remediated.xml \
  --report /tmp/report-al2023-remediated.html \
  ssg-al2023-ds.xml
```

#### B. Ubuntu Linux 24.04 LTS (Noble Numbat)
```bash
oscap xccdf eval \
  --remediate \
  --tailoring-file ssg-ubuntu2404-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_ubuntu2404_cis_l2_tcvn14423 \
  --oval-results \
  --results /tmp/xccdf-results-ubuntu2404-remediated.xml \
  --results-arf /tmp/arf-ubuntu2404-remediated.xml \
  --report /tmp/report-ubuntu2404-remediated.html \
  ssg-ubuntu2404-ds.xml
```

#### C. Red Hat Enterprise Linux 8 (RHEL 8)
```bash
oscap xccdf eval \
  --remediate \
  --tailoring-file ssg-rhel8-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_rhel8_cis_l2_tcvn14423 \
  --oval-results \
  --results /tmp/xccdf-results-rhel8-remediated.xml \
  --results-arf /tmp/arf-rhel8-remediated.xml \
  --report /tmp/report-rhel8-remediated.html \
  ssg-rhel8-ds.xml
```

#### D. Red Hat Enterprise Linux 9 (RHEL 9)
```bash
oscap xccdf eval \
  --remediate \
  --tailoring-file ssg-rhel9-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_rhel9_cis_l2_tcvn14423 \
  --oval-results \
  --results /tmp/xccdf-results-rhel9-remediated.xml \
  --results-arf /tmp/arf-rhel9-remediated.xml \
  --report /tmp/report-rhel9-remediated.html \
  ssg-rhel9-ds.xml
```

---

### 3.2. Phương thức 2: Xuất Kịch bản Khắc phục CHỈ CHO CÁC CHECK BỊ FAIL (Khuyến nghị Chuẩn Production)
Để kiểm soát tuyệt đối các thay đổi trên máy chủ Production, quy trình chuẩn gồm 2 bước:
1. **Bước 1**: Quét hệ thống và lưu kết quả ra file XML (`/tmp/xccdf-results-<os>.xml` như hướng dẫn ở Mục 2).
2. **Bước 2**: Truyền file kết quả `xccdf-results-<os>.xml` vào lệnh `generate fix`. OpenSCAP sẽ **CHỈ trích xuất các đoạn fix cho đúng những quy tắc có kết quả `fail`** trong phiên quét đó!

#### A. Xuất Bash Script CHỈ cho các Check bị Fail:
```bash
# 1. Amazon Linux 2023:
oscap xccdf generate fix \
  --fix-type bash \
  --output /tmp/remediate-failed-only-al2023.sh \
  /tmp/xccdf-results-al2023.xml

# 2. Ubuntu Linux 24.04:
oscap xccdf generate fix \
  --fix-type bash \
  --output /tmp/remediate-failed-only-ubuntu2404.sh \
  /tmp/xccdf-results-ubuntu2404.xml

# 3. RHEL 8:
oscap xccdf generate fix \
  --fix-type bash \
  --output /tmp/remediate-failed-only-rhel8.sh \
  /tmp/xccdf-results-rhel8.xml

# 4. RHEL 9:
oscap xccdf generate fix \
  --fix-type bash \
  --output /tmp/remediate-failed-only-rhel9.sh \
  /tmp/xccdf-results-rhel9.xml

# Thao tác Review và Thực thi Bash Script:
less /tmp/remediate-failed-only-<os>.sh        # Xem trước đúng các lệnh fix cần chạy
sudo bash /tmp/remediate-failed-only-<os>.sh   # Thực thi áp dụng
```

#### B. Xuất Ansible Playbook CHỈ cho các Check bị Fail:
```bash
# 1. Amazon Linux 2023:
oscap xccdf generate fix \
  --fix-type ansible \
  --output /tmp/remediate-failed-only-al2023.yml \
  /tmp/xccdf-results-al2023.xml

# 2. Ubuntu Linux 24.04:
oscap xccdf generate fix \
  --fix-type ansible \
  --output /tmp/remediate-failed-only-ubuntu2404.yml \
  /tmp/xccdf-results-ubuntu2404.xml

# 3. RHEL 8:
oscap xccdf generate fix \
  --fix-type ansible \
  --output /tmp/remediate-failed-only-rhel8.yml \
  /tmp/xccdf-results-rhel8.xml

# 4. RHEL 9:
oscap xccdf generate fix \
  --fix-type ansible \
  --output /tmp/remediate-failed-only-rhel9.yml \
  /tmp/xccdf-results-rhel9.xml

# Thao tác chạy Playbook qua Ansible:
ansible-playbook -i localhost, -c local /tmp/remediate-failed-only-<os>.yml
```

> [!TIP]
> **Khác biệt khi truyền Datastream XML vs Results XML**:
> - Nếu truyền file Datastream gốc (`generate fix ... ssg-<os>-ds.xml`): OpenSCAP sẽ xuất fix cho **toàn bộ profile** (kể cả những rule hệ thống đã pass). Dùng khi muốn build image sạch từ đầu.
> - Nếu truyền file kết quả scan (`generate fix ... xccdf-results.xml`): OpenSCAP sẽ **CHỈ xuất fix cho các quy tắc đang bị `fail`** trên máy chủ mục tiêu.

---

### 3.3. Phương thức 3: Khắc phục Ngoại tuyến từ Kết quả Quét Trước đó (`oscap xccdf remediate`)
Nếu đã có tệp kết quả quét `/tmp/xccdf-results-<os>.xml` từ bước đánh giá, có thể thực hiện khắc phục trực tiếp trên kết quả đó. OpenSCAP sẽ **chỉ chạy fix cho các mục `fail`** trong file XML này mà không cần đánh giá lại toàn bộ hệ thống từ đầu:
```bash
oscap xccdf remediate \
  --results /tmp/xccdf-remediation-results-<os>.xml \
  /tmp/xccdf-results-<os>.xml
```

---

### 3.4. Quy trình Khuyến nghị & Lưu ý Vận hành An toàn
1. **Sao lưu trước khi khắc phục (Snapshot / Backup)**: Luôn chụp snapshot ổ đĩa (AWS EBS Snapshot hoặc VMware Snapshot) trước khi chạy remediation trên môi trường Production.
2. **Kiểm tra Lại sau Remediation**: Chạy lại lệnh quét đánh giá thông thường (không có cờ `--remediate`) để xác nhận các quy tắc đã chuyển trạng thái sang `pass` và báo cáo HTML cập nhật 100% tuân thủ:
   ```bash
   oscap xccdf eval \
     --tailoring-file ssg-<os>-ds-tailoring.xml \
     --profile <tailored_profile_id> \
     --report /tmp/report-<os>-verified.html \
     ssg-<os>-ds.xml
   ```
3. **Hiệu lực Cấu hình Kernel & Dịch vụ**:
   - Nạp lại cấu hình sysctl: `sysctl --system`
   - Khởi động lại các dịch vụ bảo mật nếu có thay đổi: `systemctl restart sshd`, `systemctl restart auditd` (hoặc reboot server nếu quy tắc auditd có cờ bất biến `-e 2`).

---

## 4. Danh mục Profile ID Tra cứu

| Hệ điều hành | Datastream tương ứng | Base CIS L2 Profile ID | Tailored Profile ID |
| :--- | :--- | :--- | :--- |
| **Amazon Linux 2023** | `ssg-al2023-ds.xml` | `xccdf_org.ssgproject.content_profile_cis` | `xccdf_vn.com.tcbs_profile_al2023_cis_l2_tcvn14423` |
| **Ubuntu 24.04 LTS** | `ssg-ubuntu2404-ds.xml` | `xccdf_org.ssgproject.content_profile_cis_level2_server` | `xccdf_vn.com.tcbs_profile_ubuntu2404_cis_l2_tcvn14423` |
| **RHEL 8** | `ssg-rhel8-ds.xml` | `xccdf_org.ssgproject.content_profile_cis` | `xccdf_vn.com.tcbs_profile_rhel8_cis_l2_tcvn14423` |
| **RHEL 9** | `ssg-rhel9-ds.xml` | `xccdf_org.ssgproject.content_profile_cis` | `xccdf_vn.com.tcbs_profile_rhel9_cis_l2_tcvn14423` |
