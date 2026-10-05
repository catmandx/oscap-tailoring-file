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
- **CyberArk PAM**: Quản lý mật khẩu Vaulting, OTP 24h, MFA 2FA, Session Recording, cấp quyền `NOPASSWD sudo` cho user admin được PAM quản lý, khóa trực tiếp password của `root` (bỏ qua `ensure_root_password_configured` vì phục hồi qua Cloud Console/IAM/Snapshot) -> Thay thế chính sách password/faillock cục bộ gây nghẽn tài khoản dịch vụ.
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

## 3. Danh mục Profile ID Tra cứu

| Hệ điều hành | Datastream tương ứng | Base CIS L2 Profile ID | Tailored Profile ID |
| :--- | :--- | :--- | :--- |
| **Amazon Linux 2023** | `ssg-al2023-ds.xml` | `xccdf_org.ssgproject.content_profile_cis` | `xccdf_vn.com.tcbs_profile_al2023_cis_l2_tcvn14423` |
| **Ubuntu 24.04 LTS** | `ssg-ubuntu2404-ds.xml` | `xccdf_org.ssgproject.content_profile_cis_level2_server` | `xccdf_vn.com.tcbs_profile_ubuntu2404_cis_l2_tcvn14423` |
| **RHEL 8** | `ssg-rhel8-ds.xml` | `xccdf_org.ssgproject.content_profile_cis` | `xccdf_vn.com.tcbs_profile_rhel8_cis_l2_tcvn14423` |
| **RHEL 9** | `ssg-rhel9-ds.xml` | `xccdf_org.ssgproject.content_profile_cis` | `xccdf_vn.com.tcbs_profile_rhel9_cis_l2_tcvn14423` |
