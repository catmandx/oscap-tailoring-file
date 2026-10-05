# BẢNG TỔNG HỢP CÁC THIẾT LẬP (XCCDF VALUES) THƯỜNG ĐƯỢC DOANH NGHIỆP TÙY BIẾN
## ĐỐI SOÁT HỒ SƠ TAILORING TCVN 14423:2026 & CIS LEVEL 2 SERVER

> **Mục đích tài liệu:**
> Thống kê toàn bộ các biến cấu hình (XCCDF Values/Parameters) trong bộ quy chuẩn OpenSCAP Benchmark (RHEL 9, RHEL 8, AL2023, Ubuntu 24.04). Chỉ rõ các giá trị mặc định của CIS, các tùy chọn khả dĩ, và các giá trị mà **Doanh nghiệp / Tổ chức thực tế thường muốn thay đổi** phù hợp với chính sách nội bộ và kiến trúc vận hành hạ tầng.

---

## 1. BẢNG TRA CỨU CÁC THIẾT LẬP THƯỜNG ĐƯỢC DOANH NGHIỆP ĐIỀU CHỈNH

| Nhóm Thiết lập | Tên biến XCCDF (Value ID) | Giá trị Mặc định CIS | Lựa chọn Khả dĩ | Giá trị Thực tế Doanh nghiệp thường đổi | Lý do & Rationale Tùy biến Doanh nghiệp |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SELinux State** | `var_selinux_state` | `enforcing` | `enforcing`, `permissive`, `disabled` | **`permissive`** *(Giai đoạn 1–2 tháng)* | **Tránh downtime do crash ứng dụng**: Hệ thống chưa từng bật SELinux cần giai đoạn Permissive để thu thập 100% AVC audit logs và tạo custom policy trước khi chuyển `enforcing`. |
| **Login Banner Text** | `login_banner_text`, `remote_login_banner_text` | `^Authorized users only...$` | Regex tùy chỉnh | **Regex theo tên Công ty** *(VD: `^TCBS Authorized Users Only...$`)* | **Nhận diện thương hiệu & Cảnh báo pháp lý**: Các tổ chức tài chính/ngân hàng luôn đưa tên công ty và điều khoản bảo mật nội bộ vào banner SSH/TTY. |
| **Login Banner Content** | `login_banner_contents`, `remote_login_banner_contents`, `motd_banner_contents` | `"Authorized users only. All activity may be monitored..."` | Văn bản tùy chỉnh | **Nội dung banner song ngữ / tiếng Việt của tổ chức** | Khớp với quy chế quản lý an toàn thông tin và văn bản pháp lý của doanh nghiệp. |
| **SSH Idle Timeout** | `sshd_idle_timeout_value` | `300` (5 phút) | `300`, `600`, `900`, `1800`, `3600` | **`900`** (15 phút) hoặc **`1800`** (30 phút) | **Tránh ngắt phiên làm việc của DevOps/DBA**: 5 phút là quá ngắn khi chạy tác vụ bảo trì dài hoặc debug; doanh nghiệp thường nới lên 15–30 phút. |
| **Session Inactivity** | `inactivity_timeout_value`, `var_logind_session_timeout` | `900` (15 phút) | `300`, `600`, `900`, `1800` | **`1800`** (30 phút) | Đồng bộ thời gian chờ nhàn rỗi phiên bash console với quy chế nội bộ. |
| **Password Max Age** | `var_accounts_maximum_age_login_defs` | `60` hoặc `90` ngày | `45`, `60`, `90`, `120`, `180`, `365` | **`90`** ngày (hoặc bỏ qua nếu dùng CyberArk PAM) | Đa số doanh nghiệp tài chính quy định chu kỳ đổi mật khẩu là 90 ngày. Nếu quản lý qua PAM thì bỏ qua cơ chế cục bộ. |
| **Password Min Age** | `var_accounts_minimum_age_login_defs` | `7` ngày (CIS) | `0`, `1`, `2`, `3`, `5`, `7` | **`1`** ngày hoặc **`0`** | Giúp người dùng có thể đổi lại mật khẩu khi cần thiết mà không phải chờ đợi 7 ngày. |
| **Password Warning** | `var_accounts_password_warn_age_login_defs` | `7` ngày | `7`, `10`, `14` | **`14`** ngày | Cho nhân viên nhiều thời gian hơn để chủ động đổi mật khẩu trước khi bị khóa. |
| **Sudo Ticket Timeout** | `var_sudo_timestamp_timeout` | `5` phút | `always_prompt`, `1`, `2`, `5`, `15` | **`15`** phút (hoặc NOPASSWD qua PAM) | Giảm tần suất gõ lại mật khẩu khi admin chạy chuỗi lệnh bảo trì hệ thống. |
| **Audit Buffer Backlog**| `var_audit_backlog_limit` | `8192` | Giá trị nguyên | **`16384`** hoặc **`32768`** | **Chống nghẽn Audit Buffer trên máy tải cao**: Các máy chủ giao dịch lớn cần buffer lớn hơn để không rớt log audit khi I/O đột biến. |
| **Audit Disk Space** | `var_auditd_space_left_percentage` | `25%` | `5%`, `25%`, `50%`, `75%` | **`10%`** hoặc **`15%`** | Các máy chủ có ổ đĩa lớn (500GB - 2TB) nếu đặt 25% sẽ kích hoạt cảnh báo quá sớm (lãng phí hàng trăm GB đĩa). |
| **User Umask** | `var_accounts_user_umask` | `027` | `022`, `027`, `077` | **`027`** (Chuẩn) / **`022`** (Dev/Build) | Môi trường Production giữ `027`; môi trường Build/CI-CD thường dùng `022` để các tool khác đọc được artifact. |
| **Kernel Panic Reboot**| `var_kernel_config_panic_timeout` | `0` (Treo máy) | `0`, `1_minute`, `5_minutes` | **`10` giây** hoặc **`60` giây** | Cho phép máy chủ tự động khởi động lại sau Kernel Panic thay vì bị treo vô thời hạn ở màn hình đen. |

---

## 2. DANH MỤC CÁC QUY TẮC ĐƯỢC TẮT CHỦ ĐỘNG (DESELECTED RULES) TRONG TAILORING TCBS

Ngoài việc thay đổi giá trị của các biến XCCDF nêu trên, TCBS áp dụng chính sách **Deselect** đối với các quy tắc sau nhờ có các biện pháp kiểm soát bù trừ tương đương hoặc cấp thiết cho hạ tầng Production:

1. **`sysctl_net_ipv4_ip_forward`**: Tắt quy tắc cấm IP Forwarding để Docker / Kubernetes Pods chuyển tiếp mạng bình thường. (Bù trừ: AWS NFW & Security Groups).
2. **`sudo_add_use_pty`**: Tắt quy tắc bắt buộc PTY để Ansible pipelining và CI/CD runners thực thi lệnh đặc quyền tự động. (Bù trừ: CyberArk PAM Video Recording + `/var/log/sudo.log`).
3. **`sysctl_net_ipv4_conf_all_rp_filter` & `default`**: Tắt kiểm tra Strict RP Filter để không làm rớt gói tin trên máy chủ nhiều card mạng, VPN tunnels và K8s CNI Overlay. (Bù trừ: AWS VPC Anti-spoofing).
4. **`selinux_state`**: Gán biến `var_selinux_state = permissive` trong giai đoạn quan sát 1–2 tháng.
5. **`software-integrity` / `aide`**: Tắt AIDE quét hash định kỳ gây nghẽn I/O. (Bù trừ: Palo Alto Networks Cortex XDR).
6. **`encrypt_partitions`**: Tắt mã hóa LUKS cục bộ yêu cầu gõ pass khi reboot. (Bù trừ: 100% AWS EBS KMS AES-256 & VMware Encryption).
7. **`disk_partitioning`**: Tắt chia nhỏ ổ đĩa cục bộ. (Bù trừ: Log streaming liên tục về S3 WORM Object Lock & SIEM 24/7).
8. **`firewalld` / `ufw` / `nftables`**: Tắt tường lửa cục bộ gây xung đột iptables Docker. (Bù trừ: AWS Network Firewall & Security Groups).
9. **`faillock` / `password_pam_*`**: Tắt khóa tài khoản dịch vụ cục bộ. (Bù trừ: CyberArk PAM Vaulting, 24h OTP, MFA 2FA).
10. **`sudo_remove_nopasswd`**: Cho phép `NOPASSWD` cho tài khoản admin/automation được PAM quản trị.
11. **`audit_rules_*_file_modification`**: Tắt bắt syscalls mở/sửa/xóa file thông thường để bảo toàn I/O đĩa.
12. **`ensure_root_password_configured`**: Khóa password root (`passwd -l root`), cứu hộ qua Cloud Console/Snapshot.
13. **`package_postfix_installed`**: Không cài MTA cục bộ, chuyển tiếp cảnh báo qua SIEM / APM / SES.
14. **`package_systemd-journal-remote_installed`**: Sử dụng Elastic Filebeat / Vector stream log trực tiếp.
15. **`sshd_limit_user_access`**: Quản lý truy cập và phân quyền tập trung qua CyberArk PAM RBAC Gateway.
