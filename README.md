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
- **CyberArk PAM**: Quản lý mật khẩu Vaulting, OTP 24h, MFA 2FA, Session Recording, cấp quyền `NOPASSWD sudo` cho user admin được PAM quản lý -> Thay thế chính sách password/faillock cục bộ gây nghẽn tài khoản dịch vụ.
- **Auditd Tối ưu (Chống nghẽn I/O)**: Vô hiệu hóa toàn bộ các rule bắt syscalls sửa/xóa/mở file thông thường; giữ lại 5 nhóm sự kiện kiểm toán lõi (Danh tính, Sudoers, Process creation + param, Mạng/DNS, Tác động file log) kết hợp Cortex XDR.

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
