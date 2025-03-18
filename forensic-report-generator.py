import os
import json
import datetime
import subprocess
import platform
import socket
import hashlib
import argparse
from pathlib import Path
from collections import defaultdict
import sys
import io  # Added import for io module

# Third-party imports - need to be installed
try:
    import psutil
    import pandas as pd
    import win32evtlog
    import win32con
    import winreg
except ImportError:
    print("Please install required dependencies:")
    print("pip install psutil pandas pywin32")
    sys.exit(1)

# HTML template using Bootstrap and DataTables for interactivity
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Investigation Report</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- DataTables CSS -->
    <link href="https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <!-- Custom styles -->
    <style>
        body {{
            padding: 20px;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }}
        .header {{
            margin-bottom: 30px;
            border-bottom: 1px solid #dee2e6;
            padding-bottom: 15px;
        }}
        .filters {{
            margin-bottom: 20px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .severity-high {{
            background-color: #f8d7da !important;
        }}
        .severity-medium {{
            background-color: #fff3cd !important;
        }}
        .severity-low {{
            background-color: #d1e7dd !important;
        }}
        .severity-info {{
            background-color: #cfe2ff !important;
        }}
        .category-badge {{
            font-size: 0.8em;
            padding: 4px 8px;
            border-radius: 4px;
            background-color: #6c757d;
            color: white;
        }}
        .summary-card {{
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        pre {{
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            white-space: pre-wrap;
            max-height: 400px;
            overflow-y: auto;
        }}
        .dataTables_filter {{
            display: none;
        }}
        .badge-high {{
            background-color: #dc3545;
            color: white;
        }}
        .badge-medium {{
            background-color: #ffc107;
            color: black;
        }}
        .badge-low {{
            background-color: #198754;
            color: white;
        }}
        .badge-info {{
            background-color: #0d6efd;
            color: white;
        }}
    </style>
</head>
<body>
    <div class="container-fluid">
        <!-- Header -->
        <div class="header">
            <h1>Forensic Investigation Report</h1>
            <div class="row">
                <div class="col-md-6">
                    <p><strong>Generated:</strong> {timestamp}</p>
                    <p><strong>System:</strong> {hostname}</p>
                </div>
                <div class="col-md-6">
                    <p><strong>OS:</strong> {os_info}</p>
                    <p><strong>Findings:</strong> {total_findings} ({high_count} high, {medium_count} medium, {low_count} low, {info_count} info)</p>
                </div>
            </div>
        </div>
        
        <!-- Summary -->
        <div class="row mb-4">
            <div class="col-md-12">
                <div class="card summary-card">
                    <div class="card-header">
                        <h5 class="card-title">Investigation Summary</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            {category_summary}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Filters -->
        <div class="filters card mb-4">
            <div class="card-body">
                <h5 class="card-title">Filters</h5>
                <div class="row">
                    <div class="col-md-4 mb-2">
                        <label for="categoryFilter" class="form-label">Category:</label>
                        <select id="categoryFilter" class="form-select">
                            <option value="">All Categories</option>
                            {category_options}
                        </select>
                    </div>
                    <div class="col-md-4 mb-2">
                        <label for="severityFilter" class="form-label">Severity:</label>
                        <select id="severityFilter" class="form-select">
                            <option value="">All Severities</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                            <option value="info">Info</option>
                        </select>
                    </div>
                    <div class="col-md-4 mb-2">
                        <label for="customSearch" class="form-label">Search:</label>
                        <input type="text" id="customSearch" class="form-control" placeholder="Search...">
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Findings Table -->
        <div class="card">
            <div class="card-header">
                <h5 class="card-title">Forensic Findings</h5>
            </div>
            <div class="card-body">
                <table id="forensicTable" class="table table-striped table-bordered" style="width:100%">
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Severity</th>
                            <th>Title</th>
                            <th>Description</th>
                            <th>Timestamp</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_rows}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <!-- jQuery -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <!-- DataTables JS -->
    <script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js"></script>
    
    <script>
        $(document).ready(function() {{
            // Initialize DataTable
            var table = $('#forensicTable').DataTable({{
                order: [[1, 'asc'], [0, 'asc']],
                pageLength: 25,
                lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, "All"]],
                columnDefs: [
                    {{
                        targets: 1, // Severity column
                        render: function(data, type, row) {{
                            const severity = data.toLowerCase();
                            return '<span class="badge badge-' + severity + '">' + data + '</span>';
                        }}
                    }}
                ]
            }});
            
            // Add custom filter functionality
            $('#categoryFilter').on('change', function() {{
                table.column(0).search(this.value).draw();
            }});
            
            $('#severityFilter').on('change', function() {{
                table.column(1).search(this.value, true, false).draw();
            }});
            
            $('#customSearch').on('keyup', function() {{
                table.search(this.value).draw();
            }});
            
            // Apply row coloring based on severity
            $('#forensicTable tbody tr').each(function() {{
                const severity = $(this).find('td:eq(1)').text().trim().toLowerCase();
                $(this).addClass('severity-' + severity);
            }});
            
            // Modal functionality for details
            $('button[data-bs-toggle="modal"]').on('click', function() {{
                const modalId = $(this).data('bs-target');
                $(modalId).modal('show');
            }});
        }});
    </script>
</body>
</html>
"""

class ForensicCollector:
    def __init__(self, output_path="forensic_report.html", verbose=True):
        self.output_path = output_path
        self.findings = []
        self.categories = set()
        self.verbose = verbose
        self.system_info = self._get_system_info()
        
        # Define known legitimate Windows processes
        self.legitimate_processes = {
            "svchost.exe", "csrss.exe", "winlogon.exe", "services.exe", 
            "lsass.exe", "smss.exe", "explorer.exe", "spoolsv.exe", 
            "dwm.exe", "taskhostw.exe", "sihost.exe", "ctfmon.exe",
            "SearchApp.exe", "ShellExperienceHost.exe", "StartMenuExperienceHost.exe",
            "RuntimeBroker.exe", "SgrmBroker.exe", "SecurityHealthService.exe",
            "fontdrvhost.exe", "dllhost.exe", "SearchIndexer.exe",
            "wininit.exe", "conhost.exe", "WmiPrvSE.exe", "MsMpEng.exe",
            "NisSrv.exe", "MemCompression", "Registry", "Idle", "System",
            "MsMpEng.exe", "msdtc.exe", "TrustedInstaller.exe", "dasHost.exe"
        }
        
        # Define common system paths
        self.system_paths = {
            os.environ.get('SYSTEMROOT', 'C:\\Windows'),
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32'),
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'SysWOW64'),
            os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files')),
            os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'))
        }
        
        # Define common registry run keys
        self.common_autorun_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        ]
        
        # Define known legitimate services
        self.legitimate_services = {
            "wuauserv", "wscsvc", "windefend", "WSearch", "wuauserv", 
            "Dnscache", "DHCP", "Spooler", "EventLog", "Schedule", 
            "PlugPlay", "LanmanWorkstation", "LanmanServer", "BITS",
            "Browser", "CryptSvc", "EventSystem", "DPS", "iphlpsvc"
        }
        
        # Define known legitimate scheduled tasks
        self.legitimate_scheduled_tasks = {
            "\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
            "\\Microsoft\\Windows\\Autochk\\Proxy",
            "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
            "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
            "\\Microsoft\\Windows\\Diagnosis\\Scheduled",
            "\\Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector",
            "\\Microsoft\\Windows\\Maintenance\\WinSAT",
            "\\Microsoft\\Windows\\Power Efficiency Diagnostics\\AnalyzeSystem",
            "\\Microsoft\\Windows\\Registry\\RegIdleBackup",
            "\\Microsoft\\Windows\\Time Synchronization\\SynchronizeTime",
            "\\Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance",
            "\\Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup",
            "\\Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan",
            "\\Microsoft\\Windows\\Windows Defender\\Windows Defender Verification",
            "\\Microsoft\\Windows\\WindowsUpdate\\Automatic App Update",
            "\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start"
        }
        
    def log(self, message):
        """Print log message if verbose mode is enabled"""
        if self.verbose:
            print(message)
    
    def _get_system_info(self):
        """Collect system information"""
        return {
            "hostname": socket.gethostname(),
            "os_info": f"{platform.system()} {platform.release()} ({platform.version()})",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def add_finding(self, category, severity, title, description, details, timestamp=None):
        """Add a finding to the report"""
        if timestamp is None:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        self.categories.add(category)
        self.findings.append({
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "details": details,
            "timestamp": timestamp
        })
    
    def collect_running_processes(self):
        """Collect and analyze running processes"""
        self.log("Collecting running processes...")
        
        # Get all running processes
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
            try:
                process_info = proc.info
                
                # Skip if it's a known legitimate process with a standard path
                process_name = process_info['name'].lower() if process_info['name'] else ""
                process_path = process_info['exe'] if process_info['exe'] else ""
                
                # Skip legitimate processes in system paths
                if (process_name in self.legitimate_processes and 
                    any(process_path.startswith(path) for path in self.system_paths if process_path)):
                    continue
                
                # Check for suspicious characteristics
                is_suspicious = False
                suspicion_reasons = []
                
                # Check if process is running from temp or download directories
                suspicious_dirs = ['\\temp\\', '\\tmp\\', '\\downloads\\', '\\appdata\\local\\temp\\']
                if process_path and any(susp_dir in process_path.lower() for susp_dir in suspicious_dirs):
                    is_suspicious = True
                    suspicion_reasons.append(f"Process running from suspicious location: {process_path}")
                
                # Check for processes with no name
                if not process_name:
                    is_suspicious = True
                    suspicion_reasons.append("Process has no name")
                
                # Check for processes with unusual names (random strings)
                if process_name and len(process_name) >= 8:
                    random_looking = all(c.isalnum() for c in process_name.replace('.exe', ''))
                    if random_looking and len(set(process_name.replace('.exe', ''))) > 6:
                        is_suspicious = True
                        suspicion_reasons.append(f"Process has possibly random name: {process_name}")
                
                # Check for system process names not in system directories
                if (process_name in self.legitimate_processes and 
                    process_path and 
                    not any(process_path.startswith(path) for path in self.system_paths)):
                    is_suspicious = True
                    suspicion_reasons.append(f"System process name running from non-system location: {process_path}")
                
                # Add to findings if suspicious
                if is_suspicious:
                    severity = "high" if len(suspicion_reasons) > 1 else "medium"
                    process_details = {
                        "PID": process_info['pid'],
                        "Name": process_info['name'],
                        "Path": process_info['exe'],
                        "Command Line": ' '.join(process_info['cmdline']) if process_info['cmdline'] else "",
                        "User": process_info['username'],
                        "Created": datetime.datetime.fromtimestamp(process_info['create_time']).strftime("%Y-%m-%d %H:%M:%S") if process_info['create_time'] else "",
                        "Suspicion Reasons": suspicion_reasons
                    }
                    
                    self.add_finding(
                        category="Processes",
                        severity=severity,
                        title=f"Suspicious Process: {process_info['name'] or 'Unknown'}",
                        description=f"Process with suspicious characteristics: {', '.join(suspicion_reasons)}",
                        details=json.dumps(process_details, indent=2)
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    
    def collect_network_connections(self):
        """Collect and analyze network connections"""
        self.log("Collecting network connections...")
        
        # Get all network connections
        connections = psutil.net_connections(kind='all')
        
        for conn in connections:
            try:
                # Skip connections with no PID
                if conn.pid is None:
                    continue
                
                # Get process info
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                    proc_path = proc.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "Unknown"
                    proc_path = "Unknown"
                
                # Skip if it's a known legitimate process with expected connections
                if (proc_name.lower() in self.legitimate_processes and 
                    any(proc_path.startswith(path) for path in self.system_paths if proc_path != "Unknown")):
                    # Still record connections to unusual ports or foreign addresses
                    if conn.laddr and conn.raddr:
                        local_port = conn.laddr.port
                        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "None"
                        
                        # Only flag truly unusual ports (excluding common service ports and ephemeral ports)
                        common_ports = {80, 443, 53, 123, 67, 68, 137, 138, 139, 445, 3389, 5985, 5986}
                        ephemeral_ports = set(range(49152, 65536))
                        
                        if (conn.raddr and 
                            conn.raddr.port not in common_ports and 
                            conn.raddr.port not in ephemeral_ports and
                            # Check for unusual IP patterns (private IPs are usually fine)
                            not conn.raddr.ip.startswith(('10.', '192.168.', '172.16.'))):
                            
                            connection_details = {
                                "Process": proc_name,
                                "PID": conn.pid,
                                "Local Address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "None",
                                "Remote Address": remote_addr,
                                "Status": conn.status,
                                "Process Path": proc_path
                            }
                            
                            self.add_finding(
                                category="Network",
                                severity="medium",
                                title=f"Unusual Network Connection: {proc_name}",
                                description=f"Process {proc_name} has a connection to unusual port {conn.raddr.port if conn.raddr else 'Unknown'}",
                                details=json.dumps(connection_details, indent=2)
                            )
                    continue
                
                # Check for listening ports
                if conn.status == 'LISTEN':
                    if conn.laddr:
                        local_port = conn.laddr.port
                        
                        # Check if this is an unusual port for a non-system process
                        common_listening_ports = {80, 443, 3389, 5985, 5986, 135, 445, 139, 137, 8080, 8443}
                        if local_port not in common_listening_ports:
                            connection_details = {
                                "Process": proc_name,
                                "PID": conn.pid,
                                "Local Address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "None",
                                "Status": conn.status,
                                "Process Path": proc_path
                            }
                            
                            self.add_finding(
                                category="Network",
                                severity="medium",
                                title=f"Unusual Listening Port: {proc_name} on port {local_port}",
                                description=f"Process {proc_name} is listening on unusual port {local_port}",
                                details=json.dumps(connection_details, indent=2)
                            )
                
                # Check for established connections to unusual destinations
                elif conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
                    
                    # Check if connecting to unusual ports (excluding common web ports)
                    if conn.raddr.port not in [80, 443, 53, 123]:
                        connection_details = {
                            "Process": proc_name,
                            "PID": conn.pid,
                            "Local Address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "None",
                            "Remote Address": remote_addr,
                            "Status": conn.status,
                            "Process Path": proc_path
                        }
                        
                        self.add_finding(
                            category="Network",
                            severity="low",
                            title=f"Connection to Unusual Port: {proc_name}",
                            description=f"Process {proc_name} has established a connection to {remote_addr}",
                            details=json.dumps(connection_details, indent=2)
                        )
            except Exception as e:
                continue
    
    def collect_autorun_entries(self):
        """Collect and analyze autorun entries in the registry"""
        self.log("Collecting autorun entries...")
        
        # Check common autorun registry keys
        for registry_key in self.common_autorun_keys:
            try:
                # Open the registry key
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key)
                
                # Enumerate the values
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        i += 1
                        
                        # Check if this is a suspicious autorun entry
                        is_suspicious = False
                        suspicion_reasons = []
                        
                        # Check for autorun entries in suspicious locations
                        suspicious_dirs = ['\\temp\\', '\\tmp\\', '\\downloads\\', '\\appdata\\local\\temp\\']
                        if any(susp_dir in value.lower() for susp_dir in suspicious_dirs):
                            is_suspicious = True
                            suspicion_reasons.append(f"Autorun entry points to suspicious location: {value}")
                        
                        # Check for entries not in system paths
                        if not any(value.lower().startswith(path.lower()) for path in self.system_paths):
                            # Not necessarily suspicious if it's a trusted program location
                            if value.lower().endswith(('.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js')):
                                suspicion_reasons.append(f"Autorun entry points to non-system executable: {value}")
                        
                        # Add to findings if suspicious
                        if is_suspicious or len(suspicion_reasons) > 0:
                            severity = "high" if is_suspicious else "low"
                            autorun_details = {
                                "Registry Key": registry_key,
                                "Name": name,
                                "Value": value,
                                "Suspicion Reasons": suspicion_reasons
                            }
                            
                            self.add_finding(
                                category="Autoruns",
                                severity=severity,
                                title=f"{'Suspicious' if is_suspicious else 'Unusual'} Autorun Entry: {name}",
                                description=f"Autorun entry with {'suspicious' if is_suspicious else 'unusual'} characteristics: {', '.join(suspicion_reasons)}",
                                details=json.dumps(autorun_details, indent=2)
                            )
                    except OSError:
                        break
                
                winreg.CloseKey(key)
            except FileNotFoundError:
                continue
            except Exception as e:
                self.log(f"Error accessing registry key {registry_key}: {e}")
    
    def collect_scheduled_tasks(self):
        """Collect and analyze scheduled tasks"""
        self.log("Collecting scheduled tasks...")
        
        try:
            # Use schtasks command to get all tasks
            result = subprocess.run(['schtasks', '/query', '/fo', 'csv', '/v'], 
                                  capture_output=True, text=True, check=True)
            
            # Parse the CSV output
            if result.stdout:
                tasks_df = pd.read_csv(
                    io.StringIO(result.stdout), 
                    skiprows=0 if result.stdout.startswith('"') else 1
                )
                
                # Clean up column names
                tasks_df.columns = [col.strip('"').strip() for col in tasks_df.columns]
                
                # Find the task name and command columns (they might have different names)
                task_name_col = next((col for col in tasks_df.columns if 'TaskName' in col), None)
                command_col = next((col for col in tasks_df.columns 
                                   if 'Command' in col or 'TaskToRun' in col or 'Actions' in col), None)
                
                if task_name_col and command_col:
                    for _, task in tasks_df.iterrows():
                        task_name = task[task_name_col]
                        command = task[command_col]
                        
                        # Skip if it's a known legitimate task
                        if task_name in self.legitimate_scheduled_tasks:
                            continue
                        
                        # Skip Microsoft tasks that are likely legitimate
                        if '\\Microsoft\\Windows\\' in task_name and not any(x in command.lower() for x in ['powershell -e', 'cmd /c', '.vbs', '.ps1']):
                            continue
                            
                        # Check for suspicious characteristics
                        is_suspicious = False
                        suspicion_reasons = []
                        
                        # Check for tasks running from suspicious locations
                        suspicious_dirs = ['\\temp\\', '\\tmp\\', '\\downloads\\', '\\appdata\\local\\temp\\']
                        if command and any(susp_dir in command.lower() for susp_dir in suspicious_dirs):
                            is_suspicious = True
                            suspicion_reasons.append(f"Task runs from suspicious location: {command}")
                        
                        # Check for tasks running scripts or unusual executables
                        suspicious_extensions = ['.ps1', '.vbs', '.js', '.bat', '.cmd']
                        if command and any(command.lower().endswith(ext) for ext in suspicious_extensions):
                            if not any(cmd in command.lower() for cmd in ['system32', 'syswow64', 'program files']):
                                is_suspicious = True
                                suspicion_reasons.append(f"Task runs a script from non-system location: {command}")
                        
                        # Check for tasks with obfuscated commands
                        if command and ('-enc' in command.lower() or '-encodedcommand' in command.lower() 
                                      or '-e ' in command.lower() or 'iex(' in command.lower()):
                            is_suspicious = True
                            suspicion_reasons.append(f"Task contains potentially obfuscated command: {command}")
                        
                        # Add to findings if suspicious (avoid false positives)
                        if is_suspicious:
                            severity = "high" if is_suspicious else "low"
                            
                            # Prepare details dictionary
                            task_details = {col: str(task[col]) for col in tasks_df.columns if pd.notna(task[col])}
                            task_details['Suspicion Reasons'] = suspicion_reasons
                            
                            self.add_finding(
                                category="Scheduled Tasks",
                                severity=severity,
                                title=f"{'Suspicious' if is_suspicious else 'Non-standard'} Scheduled Task: {task_name}",
                                description=f"Scheduled task with {'suspicious' if is_suspicious else 'unusual'} characteristics: {', '.join(suspicion_reasons) if suspicion_reasons else 'Non-Microsoft task'}",
                                details=json.dumps(task_details, indent=2)
                            )
        except subprocess.SubprocessError as e:
            self.log(f"Error running schtasks command: {e}")
        except Exception as e:
            self.log(f"Error collecting scheduled tasks: {e}")
    
    def collect_services(self):
        """Collect and analyze Windows services"""
        self.log("Collecting Windows services...")
        
        try:
            # Use sc query to get all services
            result = subprocess.run(['sc', 'query', 'type=', 'service', 'state=', 'all'], 
                                   capture_output=True, text=True, check=True)
            
            # Parse the output to get service names
            service_names = []
            if result.stdout:
                for line in result.stdout.splitlines():
                    if line.strip().startswith('SERVICE_NAME:'):
                        service_name = line.split(':', 1)[1].strip()
                        service_names.append(service_name)
            
            # Get details for each service
            for service_name in service_names:
                try:
                    # Skip well-known legitimate services
                    if service_name.lower() in self.legitimate_services:
                        continue
                    
                    # Get service configuration
                    config_result = subprocess.run(['sc', 'qc', service_name], 
                                                 capture_output=True, text=True, check=True)
                    
                    # Parse the output to get service details
                    service_details = {}
                    binary_path = None
                    
                    if config_result.stdout:
                        for line in config_result.stdout.splitlines():
                            line = line.strip()
                            if ': ' in line:
                                key, value = line.split(':', 1)
                                key = key.strip()
                                value = value.strip()
                                service_details[key] = value
                                
                                if key == 'BINARY_PATH_NAME':
                                    binary_path = value
                    
                    # Check for suspicious characteristics
                    is_suspicious = False
                    suspicion_reasons = []
                    
                    # Check binary path if available
                    if binary_path:
                        # Check for services running from suspicious locations
                        suspicious_dirs = ['\\temp\\', '\\tmp\\', '\\downloads\\', '\\appdata\\local\\temp\\']
                        if any(susp_dir in binary_path.lower() for susp_dir in suspicious_dirs):
                            is_suspicious = True
                            suspicion_reasons.append(f"Service runs from suspicious location: {binary_path}")
                        
                        # Check for services running scripts
                        suspicious_extensions = ['.ps1', '.vbs', '.js', '.bat', '.cmd']
                        if any(binary_path.lower().endswith(ext) for ext in suspicious_extensions):
                            is_suspicious = True
                            suspicion_reasons.append(f"Service runs a script: {binary_path}")
                        
                        # Check if the binary path doesn't point to a system location
                        # This is common for legitimate third-party services
                        if not any(binary_path.lower().startswith(path.lower()) for path in self.system_paths):
                            # Only flag if it's not in Program Files or other common locations
                            if not any(loc in binary_path.lower() for loc in ['\\program files', '\\programdata']):
                                suspicion_reasons.append(f"Service binary in unusual location: {binary_path}")
                    
                    # Add to findings if suspicious
                    if is_suspicious or (len(suspicion_reasons) > 0 and service_name.lower() not in self.legitimate_services):
                        severity = "high" if is_suspicious else "medium" if len(suspicion_reasons) > 0 else "low"
                        
                        self.add_finding(
                            category="Services",
                            severity=severity,
                            title=f"{'Suspicious' if is_suspicious else 'Unusual'} Service: {service_name}",
                            description=f"Windows service with {'suspicious' if is_suspicious else 'unusual'} characteristics: {', '.join(suspicion_reasons)}",
                            details=json.dumps(service_details, indent=2)
                        )
                except subprocess.SubprocessError:
                    continue
        except subprocess.SubprocessError as e:
            self.log(f"Error running sc command: {e}")
        except Exception as e:
            self.log(f"Error collecting services: {e}")
    
    def collect_recent_event_logs(self):
        """Collect and analyze recent Windows event logs"""
        self.log("Collecting event logs...")
        
        # Define important event log channels
        log_types = ["System", "Security", "Application"]
        
        # Define suspicious event IDs with their categories and descriptions
        suspicious_events = {
            # Security log
            4625: {"category": "Authentication", "severity": "medium", "description": "Failed logon attempt"},
            4648: {"category": "Authentication", "severity": "medium", "description": "Logon using explicit credentials"},
            4672: {"category": "Privileges", "severity": "medium", "description": "Special privileges assigned to new logon"},
            4720: {"category": "User Management", "severity": "medium", "description": "User account created"},
            4722: {"category": "User Management", "severity": "medium", "description": "User account enabled"},
            4724: {"category": "User Management", "severity": "medium", "description": "Password reset attempt"},
            4728: {"category": "Group Management", "severity": "medium", "description": "Member added to security-enabled global group"},
            4732: {"category": "Group Management", "severity": "medium", "description": "Member added to security-enabled local group"},
            
            # System log
            7045: {"category": "Service", "severity": "high", "description": "New service installed"},
            7040: {"category": "Service", "severity": "medium", "description": "Service start type changed"},
            104: {"category": "Event Log", "severity": "high", "description": "Event log cleared"},
            1102: {"category": "Event Log", "severity": "high", "description": "Audit log cleared"}
        }
        
        for log_type in log_types:
            try:
                # Try to open the event log - may fail if not running as administrator
                # especially for the Security log
                try:
                    hand = win32evtlog.OpenEventLog(None, log_type)
                    
                    # Read the most recent events (limit to last 100 for performance)
                    events = win32evtlog.ReadEventLog(
                        hand, 
                        win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                        0
                    )
                except Exception as e:
                    self.log(f"Error reading {log_type} event log: {e}")
                    self.add_finding(
                        category="Event Logs",
                        severity="info",
                        title=f"Could not access {log_type} event log",
                        description=f"Access to {log_type} event log was denied. Run the script as administrator for full access.",
                        details=json.dumps({"Error": str(e)}, indent=2)
                    )
                    continue
                
                event_count = 0
                failed_logon_counts = defaultdict(int)
                
                while events and event_count < 100:
                    for event in events:
                        event_count += 1
                        event_id = event.EventID & 0xFFFF  # Mask out the high bits
                        
                        # Check if this is a suspicious event
                        if event_id in suspicious_events:
                            event_info = suspicious_events[event_id]
                            
                            # For failed logons, track frequency
                            if event_id == 4625:  # Failed logon
                                try:
                                    data = event.StringInserts
                                    if data and len(data) > 5:
                                        username = data[5]
                                        source_ip = data[19] if len(data) > 19 else "N/A"
                                        failed_logon_counts[(username, source_ip)] += 1
                                        
                                        # Skip reporting individual failed logons (we'll summarize later)
                                        continue
                                except:
                                    pass
                            
                            # Get event details
                            try:
                                data = event.StringInserts
                                computer = event.ComputerName
                                time_generated = event.TimeGenerated.Format()
                                
                                # Create details dictionary
                                event_details = {
                                    "Event ID": event_id,
                                    "Source": event.SourceName,
                                    "Time": time_generated,
                                    "Computer": computer,
                                    "Category": event_info["category"],
                                    "Data": data if data else []
                                }
                                
                                # Special handling for certain event types
                                description = event_info["description"]
                                severity = event_info["severity"]
                                
                                if event_id == 7045:  # New service
                                    service_name = data[0] if data else "Unknown"
                                    service_path = data[1] if len(data) > 1 else "Unknown"
                                    
                                    # Check if the service path is suspicious
                                    suspicious_dirs = ['\\temp\\', '\\tmp\\', '\\downloads\\', '\\appdata\\local\\temp\\']
                                    if any(susp_dir in service_path.lower() for susp_dir in suspicious_dirs):
                                        description = f"Suspicious service installed: {service_name} with path {service_path}"
                                        severity = "high"
                                    else:
                                        description = f"New service installed: {service_name}"
                                        # Reduce severity for common locations
                                        if any(loc in service_path.lower() for loc in ['\\program files', '\\windows']):
                                            severity = "low"
                                
                                elif event_id == 104 or event_id == 1102:  # Log cleared
                                    description = f"Event log cleared: {log_type}"
                                
                                # Add to findings
                                self.add_finding(
                                    category=f"Event Log ({log_type})",
                                    severity=severity,
                                    title=f"Event ID {event_id}: {event_info['description']}",
                                    description=description,
                                    details=json.dumps(event_details, indent=2),
                                    timestamp=time_generated
                                )
                            except Exception as e:
                                continue
                    
                    # Get more events if we haven't reached our limit
                    if event_count < 100:
                        events = win32evtlog.ReadEventLog(
                            hand, 
                            win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                            0
                        )
                    else:
                        break
                
                # Add a finding for accounts with multiple failed logons
                for (username, source_ip), count in failed_logon_counts.items():
                    if count >= 3:  # Threshold for suspicious activity
                        severity = "high" if count >= 10 else "medium"
                        
                        self.add_finding(
                            category="Authentication",
                            severity=severity,
                            title=f"Multiple Failed Logon Attempts: {username}",
                            description=f"{count} failed logon attempts for user {username} from {source_ip}",
                            details=json.dumps({
                                "Username": username,
                                "Source IP": source_ip,
                                "Count": count,
                                "Log Type": log_type
                            }, indent=2)
                        )
                
                # Close the event log
                win32evtlog.CloseEventLog(hand)
            except Exception as e:
                self.log(f"Error reading {log_type} event log: {e}")
    
    def collect_file_system_anomalies(self):
        """Check for suspicious files in key locations"""
        self.log("Checking for suspicious files...")
        
        # Define suspicious locations to check
        locations = [
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'Temp'),
            os.environ.get('TEMP', 'C:\\Windows\\Temp'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Temp')
        ]
        
        # Define suspicious file extensions
        suspicious_extensions = ['.ps1', '.vbs', '.hta', '.bat', '.cmd', '.js', '.wsh', '.jse', '.vbe', '.pif']
        executable_extensions = ['.exe', '.dll', '.scr']
        
        # Check each location
        for location in locations:
            if not os.path.exists(location):
                continue
                
            try:
                # Get recently modified files
                now = datetime.datetime.now()
                recent_threshold = now - datetime.timedelta(days=7)
                
                for root, _, files in os.walk(location):
                    for file in files:
                        try:
                            file_path = os.path.join(root, file)
                            file_ext = os.path.splitext(file)[1].lower()
                            
                            # Check modification time
                            try:
                                mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                                is_recent = mod_time > recent_threshold
                            except:
                                is_recent = False
                            
                            # Skip if not recent - focus on new files
                            if not is_recent:
                                continue
                                
                            # Check for suspicious files
                            if file_ext in suspicious_extensions:
                                # Script files are potentially suspicious, especially in temp dirs
                                file_stats = os.stat(file_path)
                                file_size = file_stats.st_size
                                
                                # Read a sample of the file content
                                try:
                                    with open(file_path, 'rb') as f:
                                        content = f.read(4096)  # Read the first 4KB
                                        
                                        # Try to detect if the content is encoded/obfuscated
                                        is_obfuscated = False
                                        if content:
                                            try:
                                                text_content = content.decode('utf-8', errors='ignore')
                                                if ('encodedcommand' in text_content.lower() or 
                                                    '-enc ' in text_content.lower() or 
                                                    'FromBase64String' in text_content or
                                                    'IEX(' in text_content):
                                                    is_obfuscated = True
                                            except:
                                                pass
                                except:
                                    content = b''
                                    is_obfuscated = False
                                
                                severity = "high" if is_obfuscated else "medium"
                                file_details = {
                                    "Path": file_path,
                                    "Size": file_size,
                                    "Modified": mod_time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "Is Obfuscated": is_obfuscated
                                }
                                
                                self.add_finding(
                                    category="Suspicious Files",
                                    severity=severity,
                                    title=f"{'Potentially Obfuscated' if is_obfuscated else 'Suspicious'} Script: {file}",
                                    description=f"{'Potentially obfuscated' if is_obfuscated else 'Suspicious'} script file found in {root}",
                                    details=json.dumps(file_details, indent=2),
                                    timestamp=mod_time.strftime("%Y-%m-%d %H:%M:%S")
                                )
                            
                            # Check for executables in temp directories
                            elif file_ext in executable_extensions and 'temp' in location.lower():
                                # Compute file hash
                                try:
                                    hash_md5 = hashlib.md5()
                                    with open(file_path, "rb") as f:
                                        for chunk in iter(lambda: f.read(4096), b""):
                                            hash_md5.update(chunk)
                                    md5_hash = hash_md5.hexdigest()
                                except:
                                    md5_hash = "Could not compute hash"
                                
                                file_details = {
                                    "Path": file_path,
                                    "Size": os.path.getsize(file_path),
                                    "Modified": mod_time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "MD5 Hash": md5_hash
                                }
                                
                                self.add_finding(
                                    category="Suspicious Files",
                                    severity="medium",
                                    title=f"Executable in Temp Directory: {file}",
                                    description=f"Executable file found in temporary directory {root}",
                                    details=json.dumps(file_details, indent=2),
                                    timestamp=mod_time.strftime("%Y-%m-%d %H:%M:%S")
                                )
                        except Exception as e:
                            continue
            except Exception as e:
                self.log(f"Error checking location {location}: {e}")
    
    def collect_all_data(self):
        """Collect all forensic data"""
        # Collect different types of data
        self.collect_running_processes()
        self.collect_network_connections()
        self.collect_autorun_entries()
        self.collect_scheduled_tasks()
        self.collect_services()
        self.collect_recent_event_logs()
        self.collect_file_system_anomalies()
        
    def generate_report(self):
        """Generate the HTML report"""
        self.log("Generating HTML report...")
        
        # Count findings by severity
        severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            severity = finding["severity"].lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Count findings by category
        category_counts = defaultdict(int)
        for finding in self.findings:
            category_counts[finding["category"]] += 1
        
        # Generate category summary
        category_summary = ""
        for category, count in category_counts.items():
            category_summary += f"""
            <div class="col-md-4 mb-3">
                <div class="card">
                    <div class="card-body">
                        <h6 class="card-title">{category}</h6>
                        <p class="card-text">{count} findings</p>
                    </div>
                </div>
            </div>
            """
        
        # Generate category options for filter
        category_options = ""
        for category in sorted(self.categories):
            category_options += f'<option value="{category}">{category}</option>\n'
        
        # Generate table rows
        table_rows = ""
        for idx, finding in enumerate(self.findings):
            # Format timestamp
            timestamp = finding["timestamp"]
            
            # Format details
            details = finding["details"].replace('"', '&quot;')
            
            # Generate row
            table_rows += f"""
            <tr>
                <td>{finding["category"]}</td>
                <td>{finding["severity"].title()}</td>
                <td>{finding["title"]}</td>
                <td>{finding["description"]}</td>
                <td>{timestamp}</td>
                <td>
                    <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#detailsModal{idx}">
                        View Details
                    </button>
                    <div class="modal fade" id="detailsModal{idx}" tabindex="-1" aria-labelledby="detailsModalLabel{idx}" aria-hidden="true">
                        <div class="modal-dialog modal-lg">
                            <div class="modal-content">
                                <div class="modal-header">
                                    <h5 class="modal-title" id="detailsModalLabel{idx}">{finding["title"]}</h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                </div>
                                <div class="modal-body">
                                    <pre>{details}</pre>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </td>
            </tr>
            """
        
        # Fill in the template
        html_content = HTML_TEMPLATE.format(
            timestamp=self.system_info["timestamp"],
            hostname=self.system_info["hostname"],
            os_info=self.system_info["os_info"],
            total_findings=len(self.findings),
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            info_count=severity_counts["info"],
            category_summary=category_summary,
            category_options=category_options,
            table_rows=table_rows
        )
        
        # Write to file
        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.log(f"Report generated: {os.path.abspath(self.output_path)}")
        return os.path.abspath(self.output_path)

def main():
    """Main function to run the forensic collector"""
    parser = argparse.ArgumentParser(description='Windows Forensic Report Generator')
    parser.add_argument('-o', '--output', default='forensic_report.html', help='Output HTML file path')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (suppress output)')
    args = parser.parse_args()
    
    # Create collector
    collector = ForensicCollector(output_path=args.output, verbose=not args.quiet)
    
    # Collect data
    print(f"Starting forensic data collection at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    collector.collect_all_data()
    
    # Generate report
    report_path = collector.generate_report()
    print(f"Forensic report generated: {report_path}")
    print(f"Found {len(collector.findings)} potential findings:")
    
    # Count by severity
    severity_counts = defaultdict(int)
    for finding in collector.findings:
        severity_counts[finding["severity"]] += 1
    
    for severity, count in severity_counts.items():
        print(f"  - {severity.title()}: {count}")
    
    print("Open the HTML report in your browser to view the detailed findings.")

if __name__ == "__main__":
    main()
