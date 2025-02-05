# Apache 2.4 STIG Checking Tools

This directory contains tools and resources for checking Apache 2.4 STIG compliance.

## Contents

- `apache_stig_check.py` - Python script that parses Apache STIG XML and generates bash check scripts
- `apache_stig_check.sh` - Generated bash script that performs the actual compliance checks
- `U_Apache_Server_2-4_Unix_Server_V3R2_Manual_STIG/` - Latest Apache Server STIG manual checks
- `U_Apache_Server_2-4_Unix_Site_V2R5_Manual_STIG/` - Apache Site STIG manual checks
- `U_Apache_Server_2-4_Unix_Overview.pdf` - STIG overview documentation
- `U_Apache_Server_2-4_Unix_Revision_History.pdf` - STIG revision history

## Usage

1. To generate a new check script:
```bash
./apache_stig_check.py U_Apache_Server_2-4_Unix_Server_V3R2_Manual_STIG/U_Apache_Server_2-4_UNIX_Server_STIG_V3R2_Manual-xccdf.xml
```

2. To run the checks:
```bash
sudo ./apache_stig_check.sh
```

Note: Apache2 must be installed on the system for the checks to run properly.
