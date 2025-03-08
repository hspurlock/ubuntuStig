# CSV Report Feature for STIG Compliance Checks

## Overview

The CSV report feature allows you to generate a structured, machine-readable report of STIG compliance check results in CSV format. This makes it easier to:

- Import results into spreadsheet applications for analysis
- Generate custom reports and visualizations
- Track compliance over time
- Share results with stakeholders in a standard format

## Usage

To generate a CSV report along with the standard text output, add the `--csv` flag when running the scan:

```bash
./RUN_SCAN.sh ./ubuntu_24-04_v1r1.sh results.txt --csv
```

This will generate:
- `results.txt` - The standard text output with full details
- `results.csv` - A CSV file containing structured results

You can combine the `--csv` flag with other options:

```bash
./RUN_SCAN.sh ./ubuntu_24-04_v1r1.sh results.txt --no-color --csv
```

## CSV Format

The CSV file contains the following columns:

1. **Rule ID** - The STIG rule identifier (e.g., SV-270657r1066460_rule)
2. **Title** - The title of the STIG rule
3. **Status** - The compliance status (PASS, FAIL, MANUAL, or NOT_CHECKED)
4. **Details** - Additional information about failures or issues

## Implementation Details

The CSV generation is now directly integrated into the main `RUN_SCAN.sh` script as a function, which:

1. Processes the text output from the STIG compliance check
2. Extracts rule IDs, titles, statuses, and relevant details
3. Formats the data as a properly escaped CSV file

The integrated function handles ANSI color codes in the input file and properly escapes special characters for CSV format. This integration eliminates the need for a separate external script, making the tool more self-contained and easier to maintain.
