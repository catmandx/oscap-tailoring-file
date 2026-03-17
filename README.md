# oscap-tailoring-file
Oscap scanner tailoring files for work

## Usage

### RHEL9
```
oscap xccdf eval --tailoring-file ssg-rhel9-ds-tailoring.xml --profile xccdf_vn.com.tcbs_profile_cis_server_l2 --oval-results --results /tmp/xccdf-results.xml --results-arf /tmp/arf.xml --report /tmp/report.html ssg-rhel9-ds.xml
```
