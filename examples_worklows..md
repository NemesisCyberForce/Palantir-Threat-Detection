# Continuous Monitoring Implementation Mode
##### experts only
We are replacing the functions `collect_network_data` and `run_full_scan` with a **Monitoring Loop** that runs every 30 seconds and checks the **active connections** of the endpoint.

## 1. Structural Changes in `PalantirDetector`

We introduce a new internal logbook (`self.real_connection_log`) to track connections from the entire system that are **not** initiated by the detector itself.

```python
class PalantirDetector:
    def __init__(self):
        self.alerts = []
        # NEW: Logbook for system connections (not our own)
        self.real_connection_log = defaultdict(list)
        # ... (remaining self.indicators stay the same) ...

    # log_alert remains the same
    # check_server_cert_info (formerly TLS) remains the same

    def check_system_connections(self):
        """
        Analyzes active system connections and logs them for beaconing check.
        Replaces collect_network_data logic for real endpoint monitoring.
        """
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Checking active connections...")
        now = datetime.utcnow()
        
        # Iterate over all active internet connections of the system
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr:
                remote_ip, remote_port = conn.raddr
                
                # Retrieve the process name, if possible
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name().lower() if proc.name() else 'unknown'
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = 'permission_denied'

                # Filter out the script's own connections, in case the script is still using requests.head()
                # IF YOU NO LONGER USE requests.head(), THIS FILTER CAN BE REMOVED
                if proc_name == 'python.exe' and 'palantirdetector.py' in ' '.join(psutil.Process().cmdline()):
                    continue 
                
                # Log the connection for later beaconing analysis
                key = f"{remote_ip}:{remote_port}"
                self.real_connection_log[key].append({
                    'timestamp': now,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'process': proc_name,
                    'pid': conn.pid
                })
                
                # Immediate check for critical individual indicators
                if remote_port in self.indicators['suspicious_ports']:
                    self.log_alert('MEDIUM', 'SUSPICIOUS_PORT',
                                   f'Connection to suspicious port {remote_port}',
                                   {'remote_ip': remote_ip, 'process': proc_name})
                    
                # Quick DNS detection (only if IP address is not yet resolved)
                try:
                    remote_host = socket.gethostbyaddr(remote_ip)[0]
                    for suspicious_domain in self.indicators['suspicious_domains']:
                        if suspicious_domain.replace('*', '') in remote_host:
                            self.log_alert('HIGH', 'DNS_MATCH',
                                           f'Connection to known surveillance domain {remote_host}',
                                           {'ip': remote_ip, 'process': proc_name})
                except Exception:
                    pass # Resolution not possible or necessary
```

## 2. Effective Beaconing Check

The logic in `check_beaconing_patterns` largely remains the same, but it must now use the **new log list** (`self.real_connection_log`).

```python
    def check_beaconing_patterns(self, threshold=10, window_minutes=5):
        """
        Checks for beaconing patterns in system's connection logs 
        (Threshold reduced to 10 for psutil's snapshot nature).
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
                
                # 3. CRITICAL: 5-Minute Interval Check (High-Fidelity)
                if len(recent_logs) > 1:
                    intervals = [(recent_logs[i]['timestamp'] - recent_logs[i - 1]['timestamp']).total_seconds() 
                                 for i in range(1, len(recent_logs))]
                    avg_interval = sum(intervals) / len(intervals) if intervals else 0

                    if 280 <= avg_interval <= 320:  # 5 minutes +/- 20s
                        self.log_alert('CRITICAL', 'GOV_BEACON',
                                       f'Government-style 5-minute beaconing pattern detected',
                                       {'remote_host': key, 'avg_interval': avg_interval,
                                        'total_connections': len(recent_logs), 'process_sample': recent_logs[0]['process']})
                
                # 4. HIGH: General High-Frequency Beaconing Warning
                else:
                    self.log_alert('HIGH', 'BEACON',
                                   f'High-frequency beaconing detected: {len(recent_logs)} connections',
                                   {'remote_host': key, 'total_connections': len(recent_logs), 'process_sample': recent_logs[0]['process']})

            # 5. Cleanup: Remove old logs to save memory
            self.real_connection_log[key] = recent_logs
```

## 3. The Continuous Loop (`run_monitor`)

This replaces `run_full_scan` and ensures the script operates continuously.

```python
    def run_monitor(self, interval_seconds=30):
        """Runs the detection suite in a continuous loop."""
        print("Starting Palantir Continuous Monitoring Suite...")
        print(f"Scan Interval: {interval_seconds} seconds.")
        
        while True:
            try:
                start_time = time.time()
                
                # 1. Collect and check connections (Stores data for 5-minute check)
                self.check_system_connections()
                
                # 2. Check Processes (Every cycle)
                self.check_suspicious_processes()
                
                # 3. Check Certificates (Optional, could run less often)
                # self.check_server_cert_info('example.com') 

                # 4. Check the accumulated beaconing pattern (after enough data is collected)
                self.check_beaconing_patterns()
                
                # 5. Status and Sleep
                elapsed = time.time() - start_time
                wait_time = max(0, interval_seconds - elapsed)
                
                # Console output
                print(f"Scan cycle took {elapsed:.2f}s. Waiting {wait_time:.2f}s...")
                time.sleep(wait_time)

            except KeyboardInterrupt:
                print("\nMonitoring stopped by user.")
                break
            except Exception as e:
                self.log_alert('FATAL', 'ERROR', f"Monitor loop crashed: {e}")
                time.sleep(60) # Wait time after a critical error
```

#### Important Note: 

The function `check_network_connections` is replaced by the new function `check_system_connections` because the logic has been integrated into the continuous logging. You would need to adapt the **`main()`** function to call **`detector.run_monitor()`** instead of **`detector.run_full_scan()`**.
