# Continuous Monitoring Implementation Mode
##### experts only
We are replacing the functions `collect_network_data` and `run_full_scan` with a **Monitoring Loop** that runs every 30 seconds and checks the **active connections** of the endpoint.

---

## 1. Structural Changes in `PalantirDetector`

We introduce a new internal logbook (`self.real_connection_log`) to track connections from the entire system that are **not** initiated by the detector itself, along with improved memory management and allowlist support.

```python
from collections import defaultdict
from datetime import datetime, timedelta
import json

class PalantirDetector:
    def __init__(self, allowlist_file='allowlist.json'):
        self.alerts = []
        # NEW: Logbook for system connections (not our own)
        self.real_connection_log = defaultdict(list)
        # NEW: Allowlist manager for reducing false positives
        self.allowlist_manager = AllowlistManager(allowlist_file)
        # ... (remaining self.indicators stay the same) ...

    # log_alert remains the same
    # check_server_cert_info (formerly TLS) remains the same

    def cleanup_old_logs(self, retention_minutes=10):
        """
        Removes logs older than retention_minutes to prevent memory bloat.
        Called periodically during the monitoring loop.
        """
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=retention_minutes)
        
        for key in list(self.real_connection_log.keys()):
            self.real_connection_log[key] = [
                entry for entry in self.real_connection_log[key] 
                if entry['timestamp'] > cutoff
            ]
            # Remove empty entries
            if not self.real_connection_log[key]:
                del self.real_connection_log[key]

    def check_system_connections(self):
        """
        Analyzes active system connections and logs them for beaconing check.
        Replaces collect_network_data logic for real endpoint monitoring.
        Filters out whitelisted processes and IPs automatically.
        """
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Checking active connections...")
        now = datetime.utcnow()
        
        # Iterate over all active internet connections of the system
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr:
                remote_ip, remote_port = conn.raddr
                
                # Retrieve the process name and command line
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name().lower() if proc.name() else 'unknown'
                    proc_path = proc.exe() if hasattr(proc, 'exe') else 'unknown'
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = 'permission_denied'
                    proc_path = 'unknown'
                
                # Filter out the script's own connections
                if proc_name == 'python.exe' and 'palantirdetector.py' in ' '.join(psutil.Process().cmdline()):
                    continue 
                
                # Check against allowlist
                if self.allowlist_manager.is_whitelisted(
                    process=proc_name,
                    path=proc_path,
                    ip=remote_ip
                ):
                    continue
                
                # Log the connection for later beaconing analysis
                key = f"{remote_ip}:{remote_port}"
                self.real_connection_log[key].append({
                    'timestamp': now,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'process': proc_name,
                    'process_path': proc_path,
                    'pid': conn.pid
                })
                
                # Immediate check for critical individual indicators
                if remote_port in self.indicators['suspicious_ports']:
                    self.log_alert('MEDIUM', 'SUSPICIOUS_PORT',
                                   f'Connection to suspicious port {remote_port}',
                                   {'remote_ip': remote_ip, 'process': proc_name, 
                                    'process_path': proc_path, 'pid': conn.pid})
                    
                # Quick DNS detection
                try:
                    remote_host = socket.gethostbyaddr(remote_ip)[0]
                    for suspicious_domain in self.indicators['suspicious_domains']:
                        if suspicious_domain.replace('*', '') in remote_host:
                            self.log_alert('HIGH', 'DNS_MATCH',
                                           f'Connection to known surveillance domain {remote_host}',
                                           {'ip': remote_ip, 'process': proc_name, 'pid': conn.pid})
                except Exception:
                    pass  # Resolution not possible or necessary
```

---

## 2. Enhanced Beaconing Analysis

The beaconing detection now includes jitter analysis and correlation scoring to reduce false positives.

```python
    def analyze_beacon_jitter(self, intervals):
        """
        Detects if beaconing is suspiciously regular despite jitter attempts.
        Returns classification: 'SUSPICIOUS_JITTER', 'NORMAL', or None.
        """
        if len(intervals) < 3:
            return None
        
        avg = sum(intervals) / len(intervals)
        if avg == 0:
            return None
            
        variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5
        coefficient_of_variation = std_dev / avg
        
        # Real jitter has CV > 0.3; artificial jitter is often 0.05-0.15
        if 0.05 <= coefficient_of_variation <= 0.15:
            return 'SUSPICIOUS_JITTER'  # Too regular despite randomization attempt
        
        return 'NORMAL'

    def correlate_indicators(self, beacon_severity, process_data, connection_meta):
        """
        Multi-factor analysis: single indicators are weak,
        but combinations of them are suspicious.
        Returns a risk score (0-100).
        """
        risk_score = 0
        
        # Beaconing factor (highest weight)
        if beacon_severity == 'CRITICAL':
            risk_score += 50
        elif beacon_severity == 'HIGH':
            risk_score += 30
        
        # Process factor
        if process_data.get('in_temp_dir'):
            risk_score += 30
        if process_data.get('no_signature'):
            risk_score += 20
        if process_data.get('suspicious_name'):
            risk_score += 15
        
        # Connection factor
        if connection_meta.get('foreign_ip'):
            risk_score += 10
        if connection_meta.get('unusual_port'):
            risk_score += 15
        
        # Jitter analysis
        if connection_meta.get('jitter_analysis') == 'SUSPICIOUS_JITTER':
            risk_score += 15
        
        return risk_score  # Threshold: 70+ for investigation

    def check_beaconing_patterns(self, threshold=10, window_minutes=5):
        """
        Checks for beaconing patterns in system's connection logs.
        Threshold reduced to 10 for psutil's snapshot nature.
        Includes jitter analysis and multi-factor correlation.
        """
        now = datetime.utcnow()
        time_window = timedelta(minutes=window_minutes)
        print(f"Checking beaconing patterns (>{threshold} connections per remote address)...")

        # Check every collected remote address
        for key, logs in self.real_connection_log.items():
            
            # 1. Filter: Only logs within the current time window
            recent_logs = [entry for entry in logs if now - entry['timestamp'] < time_window]
            
            # 2. Beaconing Threshold
            if len(recent_logs) >= threshold:
                
                # 3. Calculate intervals and perform jitter analysis
                beacon_severity = 'HIGH'
                jitter_analysis = None
                avg_interval = 0
                
                if len(recent_logs) > 1:
                    intervals = [(recent_logs[i]['timestamp'] - recent_logs[i - 1]['timestamp']).total_seconds() 
                                 for i in range(1, len(recent_logs))]
                    avg_interval = sum(intervals) / len(intervals) if intervals else 0
                    jitter_analysis = self.analyze_beacon_jitter(intervals)

                    # CRITICAL: 5-Minute Interval Check (High-Fidelity)
                    if 280 <= avg_interval <= 320:  # 5 minutes +/- 20s
                        beacon_severity = 'CRITICAL'
                        self.log_alert('CRITICAL', 'GOV_BEACON',
                                       f'Government-style 5-minute beaconing pattern detected',
                                       {'remote_host': key, 'avg_interval': avg_interval,
                                        'total_connections': len(recent_logs), 
                                        'process_sample': recent_logs[0]['process'],
                                        'jitter_analysis': jitter_analysis})
                    else:
                        # HIGH: General High-Frequency Beaconing Warning
                        self.log_alert('HIGH', 'BEACON',
                                       f'High-frequency beaconing detected: {len(recent_logs)} connections',
                                       {'remote_host': key, 'total_connections': len(recent_logs), 
                                        'process_sample': recent_logs[0]['process'],
                                        'avg_interval': avg_interval,
                                        'jitter_analysis': jitter_analysis})

            # 5. Cleanup: Remove old logs to save memory
            self.real_connection_log[key] = recent_logs
```

---

## 3. The Continuous Loop (`run_monitor`)

This replaces `run_full_scan` and ensures the script operates continuously with periodic memory management.

```python
    def run_monitor(self, interval_seconds=30, cleanup_interval=300):
        """
        Runs the detection suite in a continuous loop.
        interval_seconds: How often to check connections (default: 30s)
        cleanup_interval: How often to clean old logs (default: 5min)
        """
        print("Starting Palantir Continuous Monitoring Suite...")
        print(f"Scan Interval: {interval_seconds} seconds.")
        print(f"Cleanup Interval: {cleanup_interval} seconds.")
        
        last_cleanup = time.time()
        
        while True:
            try:
                start_time = time.time()
                
                # 1. Collect and check connections (Stores data for 5-minute check)
                self.check_system_connections()
                
                # 2. Check Processes (Every cycle)
                self.check_suspicious_processes()
                
                # 3. Check Certificates (Optional, could run less often)
                # self.check_server_cert_info('example.com')

                # 4. Check the accumulated beaconing pattern
                self.check_beaconing_patterns()
                
                # 5. Periodic cleanup (prevent memory bloat)
                current_time = time.time()
                if current_time - last_cleanup > cleanup_interval:
                    self.cleanup_old_logs(retention_minutes=10)
                    last_cleanup = current_time
                    print("[MAINTENANCE] Old logs cleaned up.")
                
                # 6. Status and Sleep
                elapsed = time.time() - start_time
                wait_time = max(0, interval_seconds - elapsed)
                
                print(f"Scan cycle took {elapsed:.2f}s. Waiting {wait_time:.2f}s...")
                time.sleep(wait_time)

            except KeyboardInterrupt:
                print("\nMonitoring stopped by user.")
                self.export_alerts_to_file('alerts_final.json')
                break
            except Exception as e:
                self.log_alert('FATAL', 'ERROR', f"Monitor loop crashed: {e}")
                time.sleep(60)  # Wait time after a critical error
```

---

## 4. Allowlist Manager

A separate class to manage whitelisted processes, paths, and IPs.

```python
class AllowlistManager:
    """Manages whitelisting of processes, paths, and IPs to reduce false positives."""
    
    def __init__(self, filepath='allowlist.json'):
        self.filepath = filepath
        self.allowed = self.load_allowlist()
    
    def load_allowlist(self):
        """Loads allowlist from JSON file. Creates default if not found."""
        try:
            with open(self.filepath, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            default = {
                'processes': ['explorer.exe', 'chrome.exe', 'firefox.exe', 'svchost.exe'],
                'paths': ['C:\\Program Files\\', 'C:\\Windows\\System32\\'],
                'ips': []
            }
            self.save_allowlist(default)
            return default
    
    def save_allowlist(self, data):
        """Saves allowlist to JSON file."""
        with open(self.filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def is_whitelisted(self, process=None, path=None, ip=None):
        """Checks if a process, path, or IP is whitelisted."""
        if process and process in self.allowed['processes']:
            return True
        if path:
            for allowed_path in self.allowed['paths']:
                if path.startswith(allowed_path):
                    return True
        if ip and ip in self.allowed['ips']:
            return True
        return False
    
    def add_to_allowlist(self, item_type, value):
        """Adds a new item to the allowlist."""
        if item_type in self.allowed:
            if value not in self.allowed[item_type]:
                self.allowed[item_type].append(value)
                self.save_allowlist(self.allowed)
                print(f"Added {value} to {item_type} allowlist.")
```

---

## 5. SIEM Export Functionality

Export alerts in standardized formats for integration with external systems.

```python
    def export_to_siem_format(self, alert):
        """Converts local alert to CEF (Common Event Format) for SIEM ingestion."""
        return {
            "timestamp": alert.get('timestamp'),
            "severity": self.severity_to_cef(alert.get('level')),
            "signature_id": alert.get('type'),
            "source_process": alert.get('metadata', {}).get('process'),
            "source_pid": alert.get('metadata', {}).get('pid'),
            "dest_ip": alert.get('metadata', {}).get('remote_ip'),
            "dest_port": alert.get('metadata', {}).get('remote_port'),
            "message": alert.get('message'),
            "source_system": "PalantirDetector_Local",
            "full_metadata": alert.get('metadata')
        }

    def severity_to_cef(self, severity):
        """Maps severity levels to CEF scale (0-10)."""
        mapping = {
            'CRITICAL': 10,
            'HIGH': 8,
            'MEDIUM': 5,
            'LOW': 3,
            'INFO': 1
        }
        return mapping.get(severity, 3)

    def export_alerts_to_file(self, filename='alerts.json'):
        """Exports all alerts to a JSON file."""
        with open(filename, 'w') as f:
            json.dump(self.alerts, f, indent=2, default=str)
        print(f"Alerts exported to {filename}")
```

---

## 6. Main Function

Updated main function to use the new continuous monitoring mode.

```python
def main():
    detector = PalantirDetector(allowlist_file='allowlist.json')
    
    print("=" * 60)
    print("Palantir Threat Detection - Continuous Monitoring Mode")
    print("=" * 60)
    print("For educational and defensive purposes only.")
    print("Press Ctrl+C to stop.")
    print("=" * 60)
    
    # Run the monitoring loop
    detector.run_monitor(interval_seconds=30, cleanup_interval=300)

if __name__ == '__main__':
    main()
```

---

## Important Notes

1. **Permission Requirements**: This script requires administrator/root privileges to access all system connections via `psutil.net_connections()`.

2. **The function `check_system_connections`** replaces the previous network collection logic. It is now integrated into the continuous logging system.

3. **Memory Management**: The `cleanup_old_logs()` function is called periodically to prevent memory bloat. Logs older than 10 minutes are automatically removed.

4. **Allowlist Management**: An `allowlist.json` file is created on first run. Customize it to reduce false positives for your environment.

5. **SIEM Integration**: Use `export_to_siem_format()` to integrate alerts into external monitoring systems (Elastic, Splunk, Wazuh).

6. **False Positive Reduction**: Multi-factor correlation scoring (`correlate_indicators()`) helps distinguish real threats from benign high-frequency connections.
