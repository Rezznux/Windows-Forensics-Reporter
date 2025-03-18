# Windows Forensic Reporter

![Python](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)

A powerful Python-based tool that generates interactive HTML reports for Windows forensic investigations, helping analysts distinguish between legitimate Windows activity and potentially suspicious behavior.

## Features

- **Smart Analysis**: Differentiates between normal Windows activity and suspicious behavior
  - Recognizes legitimate Windows processes and their expected locations
  - Understands common system paths and registry keys
  - Identifies known Windows services and scheduled tasks

- **Comprehensive Collection**: Gathers data from multiple sources:
  - Running processes and their properties
  - Network connections and unusual ports
  - Registry autorun entries
  - Scheduled tasks
  - Windows services
  - Event logs (Security, System, Application)
  - Suspicious files in temporary locations

- **Interactive HTML Report**:
  - Filter findings by category or severity
  - Full-text search functionality
  - Detailed view for each finding
  - Color-coded severity indicators
  - Summary dashboard
  - Mobile-friendly responsive design

- **Self-contained Reports**: HTML reports work offline and can be viewed in any modern browser with no external dependencies

![image](https://github.com/user-attachments/assets/b3b59a16-d338-429b-9c49-60d018c7e7d8)



## Requirements

- Python 3.6 or later
- Windows operating system
- Administrator privileges (recommended for full functionality)
- Required Python packages:
  - psutil
  - pandas
  - pywin32

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/windows-forensic-reporter.git
   cd windows-forensic-reporter
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

Run the script with administrator privileges for full functionality:

```
python forensic_report.py
```

This will:
1. Collect forensic data from your system
2. Analyze the data for suspicious activity
3. Generate an HTML report named `forensic_report.html` in the current directory

### Command Line Options

```
python forensic_report.py [-h] [-o OUTPUT] [-q]

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output HTML file path (default: forensic_report.html)
  -q, --quiet           Quiet mode (suppress output)
```

### Example

Generate a report with a custom filename:
```
python forensic_report.py -o investigation_report.html
```

## How It Works

The tool performs the following steps:

1. **Collection**: Gathers data from various sources using native Windows APIs and system commands
2. **Analysis**: Examines each item for suspicious characteristics
3. **Classification**: Categorizes findings and assigns severity levels
4. **Reporting**: Generates an interactive HTML report with all findings

### Severity Levels

- **High**: Potentially malicious activity that requires immediate investigation
- **Medium**: Suspicious behavior that warrants further examination
- **Low**: Unusual but likely legitimate activity
- **Info**: Informational findings with no security implications

## Customization

You can customize the detection rules by modifying the following attributes in the `ForensicCollector` class:

- `legitimate_processes`: Known legitimate Windows processes
- `system_paths`: Common system directories
- `legitimate_services`: Known legitimate Windows services
- `legitimate_scheduled_tasks`: Known legitimate scheduled tasks

## Security Considerations

- This tool is designed for legitimate forensic investigations only
- Always run this tool in a controlled environment
- The script does not modify any system files or settings
- Some findings may be false positives; manual verification is recommended

## Known Limitations

- May not detect sophisticated malware that hides using rootkit techniques
- Limited access to certain logs and resources without administrator privileges
- Performance may be slower on systems with many processes or large event logs

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [psutil](https://github.com/giampaolo/psutil) - Cross-platform process and system utilities
- [pandas](https://pandas.pydata.org/) - Data analysis and manipulation tool
- [pywin32](https://github.com/mhammond/pywin32) - Python extensions for Windows
- [Bootstrap](https://getbootstrap.com/) - Front-end framework
- [DataTables](https://datatables.net/) - Advanced tables plugin

---

**Note**: This tool is meant for educational and professional use only. Always ensure you have permission to perform forensic analysis on any system.
