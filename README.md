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

Khi hệ thống phát hiện các điểm chưa đạt chuẩn tuân thủ, OpenSCAP cung cấp khả năng tự động khắc phục (Remediation) dựa trên các kịch bản định sẵn trong Datastream. Nhờ việc sử dụng **Tailoring File**, toàn bộ các can thiệp có rủi ro cao (như xóa cờ unconfined của AppArmor, chặn IP Forwarding của Docker/K8s, khóa tài khoản tự động faillock) đều **được loại trừ hoàn toàn** và các giá trị cấu hình mật khẩu TCVN 6.6.2.2 sẽ được áp dụng chuẩn xác.

Có 3 phương thức thực hiện Remediation tùy theo mức độ kiểm soát rủi ro:

### 3.1. Phương thức 1: Quét và Tự động Khắc phục Trực tiếp (`--remediate`)
Tự động quét và áp dụng ngay các fix script cho các quy tắc bị Fail (chỉ áp dụng cho các rule được BẬT trong Tailoring file).

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

### 3.2. Phương thức 2: Xuất Kịch bản Khắc phục để Review / Dry-run trước khi chạy (Khuyến nghị cho Production)
Đây là phương thức an toàn nhất cho môi trường Production, cho phép DevOps / SysAdmin kiểm tra (review) toàn bộ nội dung lệnh sẽ can thiệp vào máy chủ trước khi thực thi.

#### A. Xuất Kịch bản Bash Remediation Script (`.sh`)
```bash
# 1. Amazon Linux 2023:
oscap xccdf generate fix \
  --tailoring-file ssg-al2023-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_al2023_cis_l2_tcvn14423 \
  --fix-type bash \
  --output /tmp/remediate-al2023.sh \
  ssg-al2023-ds.xml

# 2. Ubuntu Linux 24.04:
oscap xccdf generate fix \
  --tailoring-file ssg-ubuntu2404-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_ubuntu2404_cis_l2_tcvn14423 \
  --fix-type bash \
  --output /tmp/remediate-ubuntu2404.sh \
  ssg-ubuntu2404-ds.xml

# 3. RHEL 8:
oscap xccdf generate fix \
  --tailoring-file ssg-rhel8-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_rhel8_cis_l2_tcvn14423 \
  --fix-type bash \
  --output /tmp/remediate-rhel8.sh \
  ssg-rhel8-ds.xml

# 4. RHEL 9:
oscap xccdf generate fix \
  --tailoring-file ssg-rhel9-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_rhel9_cis_l2_tcvn14423 \
  --fix-type bash \
  --output /tmp/remediate-rhel9.sh \
  ssg-rhel9-ds.xml

# Thao tác Review và Thực thi Bash Script:
less /tmp/remediate-<os>.sh        # Kiểm tra nội dung script
sudo bash /tmp/remediate-<os>.sh   # Chạy khắc phục
```

#### B. Xuất Kịch bản Ansible Playbook (`.yml`)
```bash
# 1. Amazon Linux 2023:
oscap xccdf generate fix \
  --tailoring-file ssg-al2023-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_al2023_cis_l2_tcvn14423 \
  --fix-type ansible \
  --output /tmp/remediate-al2023.yml \
  ssg-al2023-ds.xml

# 2. Ubuntu Linux 24.04:
oscap xccdf generate fix \
  --tailoring-file ssg-ubuntu2404-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_ubuntu2404_cis_l2_tcvn14423 \
  --fix-type ansible \
  --output /tmp/remediate-ubuntu2404.yml \
  ssg-ubuntu2404-ds.xml

# 3. RHEL 8:
oscap xccdf generate fix \
  --tailoring-file ssg-rhel8-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_rhel8_cis_l2_tcvn14423 \
  --fix-type ansible \
  --output /tmp/remediate-rhel8.yml \
  ssg-rhel8-ds.xml

# 4. RHEL 9:
oscap xccdf generate fix \
  --tailoring-file ssg-rhel9-ds-tailoring.xml \
  --profile xccdf_vn.com.tcbs_profile_rhel9_cis_l2_tcvn14423 \
  --fix-type ansible \
  --output /tmp/remediate-rhel9.yml \
  ssg-rhel9-ds.xml

# Thao tác chạy qua Ansible cục bộ hoặc phát tán qua CI/CD / AWX:
ansible-playbook -i localhost, -c local /tmp/remediate-<os>.yml
```

---

### 3.3. Phương thức 3: Khắc phục Ngoại tuyến từ Kết quả Quét Trước đó (`oscap xccdf remediate`)
Nếu đã có tệp kết quả quét `/tmp/xccdf-results-<os>.xml` từ bước đánh giá, có thể thực hiện khắc phục trực tiếp trên kết quả đó mà không cần đánh giá lại toàn bộ từ đầu:
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
