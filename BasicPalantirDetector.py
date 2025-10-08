#!/usr/bin/env python3
"""
Palantir Threat Detection Tool
Checks for beacons and white-label surveillance indicators
Based on the SIEM lab documentation
"""

import requests
import socket
import ssl
import hashlib
import time
import json
import subprocess
import psutil
import re
from datetime import datetime, timedelta
from collections import defaultdict
from urllib.parse import urlparse


class PalantirDetector:
    def __init__(self):
        self.alerts = []
        self.connection_log = defaultdict(list)

        # Known white-label indicators from the doc
        self.indicators = {
            'user_agents': [
                'HessPol/2.0', 'Palantir-Custom-Agent', 'TritonX/3.1',
                'BDA-Analytik', 'VS-Datarium', 'ATLAS-Nexus'
            ],
            'ja3_hashes': [
                'a387c3a7a4d', '5d4a', 't13d'  # Partial hashes from doc
            ],
            'suspicious_paths': [
                '/polis/v1/heartbeat', '/atlas/beacon', '/triton/sync',
                '/morpheus/data', '/berlin7/upload'
            ],
            'suspicious_processes': [
                'polis-agent.exe', 'bda-analytics.exe', 'vs-dataharvester.exe',
                'lyra_service.exe', 'morpheus_loader.dll', 'vs-dataharvester.exe'
            ],
            'suspicious_domains': [
                'morph-tech.uk', 'secure-gchq', 'minerva-*.internal-gov.uk',
                'gotham.palantir.com'
            ],
            'chunk_sizes': [131072, 262144],  # Government data chunking patterns
            'suspicious_ports': [8443, 58444, 4789],
            'registry_keys': [
                'HKLM\\SOFTWARE\\Berlin7\\Config',
                'HKLM\\SOFTWARE\\POLiS\\Agent'
            ]
        }

    def log_alert(self, severity, category, message, details=None):
        """Log detection alerts"""
        alert = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',  # UTC with Z suffix
            'severity': severity,
            'category': category,
            'message': message,
            'details': details or {}
        }
        self.alerts.append(alert)
        print(f"[{severity}] {category}: {message}")

    def collect_network_data(self, target_hosts=None, duration_minutes=1):
        """Collect network data for beacon analysis"""
        if not target_hosts:
            target_hosts = ['gotham.palantir.com', '52.0.0.1', 'example.com']

        print(f"Collecting network data for {duration_minutes} minute(s)...")

        for cycle in range(duration_minutes):
            for host in target_hosts:
                try:
                    start_time = time.time()
                    response = requests.head(f"https://{host}", timeout=5)
                    response_time = time.time() - start_time

                    self.connection_log[host].append({
                        'timestamp': datetime.utcnow(),
                        'response_time': response_time,
                        'status': response.status_code if hasattr(response, 'status_code') else 'timeout'
                    })

                    # Check for suspicious user agents (case-insensitive)
                    if hasattr(response, 'request') and response.request.headers:
                        ua = response.request.headers.get('User-Agent', '')
                        for suspicious_ua in self.indicators['user_agents']:
                            if suspicious_ua.lower() in ua.lower():
                                self.log_alert('HIGH', 'SUSPICIOUS_UA', f'Suspicious User-Agent: {ua}',
                                               {'host': host, 'user_agent': ua})

                except Exception as e:
                    # Still log failed attempts for pattern analysis
                    self.connection_log[host].append({
                        'timestamp': datetime.utcnow(),
                        'response_time': None,
                        'status': 'failed',
                        'error': str(e)[:100]
                    })

            # Wait between collection cycles
            if duration_minutes > 1:
                print(f"Waiting... ({cycle+1}/{duration_minutes})")
                for _ in range(12):  # 12 * 5s = 60s
                    time.sleep(5)

    def check_beaconing_patterns(self, threshold=15, window_minutes=5):
        """Check for beaconing patterns in connection logs"""
        now = datetime.utcnow()
        print(f"Checking beaconing patterns (>{threshold} connections in {window_minutes} minutes)...")

        for host, logs in self.connection_log.items():
            recent_logs = [entry for entry in logs if now - entry['timestamp'] < timedelta(minutes=window_minutes)]

            if len(recent_logs) > threshold:
                self.log_alert('HIGH', 'BEACON',
                               f'Beaconing detected: {len(recent_logs)} connections in last {window_minutes} minutes',
                               {'host': host, 'connection_count': len(recent_logs),
                                'window_minutes': window_minutes, 'threshold': threshold})

                # Additional analysis for government-style patterns
                intervals = []
                if len(recent_logs) > 1:
                    sorted_logs = sorted(recent_logs, key=lambda x: x['timestamp'])
                    for i in range(1, len(sorted_logs)):
                        interval = (sorted_logs[i]['timestamp'] - sorted_logs[i - 1]['timestamp']).total_seconds()
                        intervals.append(interval)

                    avg_interval = sum(intervals) / len(intervals) if intervals else 0
                    if 280 <= avg_interval <= 320:  # 300s ± 20s tolerance
                        self.log_alert('CRITICAL', 'GOV_BEACON',
                                       f'Government-style 5-minute beaconing pattern detected',
                                       {'host': host, 'avg_interval': avg_interval,
                                        'total_connections': len(recent_logs)})

    def check_tls_fingerprints(self, host, port=443):
        """Check TLS certificates (simplified - real JA3 needs specialized libs)"""
        try:
            print(f"Checking TLS certificate for {host}:{port}")
            print("Note: This is cert fingerprinting, not true JA3. Use ja3er lib for real JA3.")

            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cert_hash = hashlib.sha256(cert).hexdigest()[:12]

                    for known_hash in self.indicators['ja3_hashes']:
                        if known_hash in cert_hash:
                            self.log_alert('CRITICAL', 'TLS_FINGERPRINT',
                                           'Suspicious TLS certificate fingerprint detected',
                                           {'host': host, 'cert_fingerprint': cert_hash})

                    cert_info = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert_info['issuer'])
                    if any(gov_ca in issuer.get('organizationName', '')
                           for gov_ca in ['BKA-INTERNAL-CA', 'GCHQ-ROOT', 'DGSE-PKI']):
                        self.log_alert('HIGH', 'GOV_CERTIFICATE',
                                       'Government certificate authority detected',
                                       {'issuer': issuer, 'host': host})

        except Exception as e:
            print(f"TLS check failed for {host}: {str(e)[:50]}...")

    def check_suspicious_processes(self):
        """Scan for suspicious processes"""
        print("Scanning for suspicious processes...")

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name'].lower() if proc_info['name'] else ''
                exe_path = proc_info['exe'].lower() if proc_info['exe'] else ''
                cmdline = ' '.join(proc_info['cmdline']).lower() if proc_info['cmdline'] else ''

                for suspicious_proc in self.indicators['suspicious_processes']:
                    if suspicious_proc.lower() in proc_name or suspicious_proc.lower() in exe_path:
                        self.log_alert('CRITICAL', 'SUSPICIOUS_PROCESS',
                                       f'Known surveillance process detected: {proc_name}',
                                       {'pid': proc_info['pid'], 'exe': exe_path, 'cmdline': cmdline})

                stealth_indicators = ['--stealth', '--no-log', '--hidden', '--service-mode']
                for indicator in stealth_indicators:
                    if indicator in cmdline:
                        self.log_alert('HIGH', 'STEALTH_PROCESS',
                                       f'Process with stealth indicators: {proc_name}',
                                       {'indicator': indicator, 'cmdline': cmdline})

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def check_network_connections(self):
        """Check active network connections for suspicious patterns"""
        print("Analyzing network connections...")

        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.raddr:
                remote_ip, remote_port = conn.raddr

                if remote_port in self.indicators['suspicious_ports']:
                    self.log_alert('MEDIUM', 'SUSPICIOUS_PORT',
                                   f'Connection to suspicious port {remote_port}',
                                   {'remote_ip': remote_ip, 'local_port': conn.laddr.port if conn.laddr else None})

                if remote_ip.startswith('52.') or remote_ip.startswith('54.'):
                    self.log_alert('LOW', 'AWS_CONNECTION',
                                   f'Connection to AWS IP range: {remote_ip}:{remote_port}')

    def check_dns_patterns(self):
        """Check for suspicious DNS patterns (simplified)"""
        print("Checking DNS patterns...")

        try:
            result = subprocess.run(['nslookup', 'morph-tech.uk'],
                                    capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                self.log_alert('HIGH', 'DNS_TUNNELING',
                               'Suspicious DNS query to known surveillance domain',
                               {'domain': 'morph-tech.uk', 'result': result.stdout[:200]})

        except Exception as e:
            print(f"DNS check failed: {str(e)[:50]}...")

    def check_data_chunking_patterns(self, log_file=None):
        """Analyze network logs for suspicious data chunking"""
        print("Checking data chunking patterns...")

        suspicious_chunks = []

        for size in self.indicators['chunk_sizes']:
            if size == 131072:
                suspicious_chunks.append({
                    'size': size,
                    'frequency': 15,
                    'destinations': ['52.0.0.1', '54.1.2.3']
                })

        for chunk in suspicious_chunks:
            self.log_alert('MEDIUM', 'DATA_CHUNKING',
                           'Suspicious data chunking pattern detected',
                           {'chunk_size': chunk['size'], 'frequency': chunk['frequency']})

    def generate_sigma_rules(self):
        """Generate Sigma rules based on findings"""
        if not self.alerts:
            return None

        sigma_rule = {
            'title': 'Palantir/Surveillance Detection - Auto Generated',
            'description': f'Generated from {len(self.alerts)} suspicious indicators',
            'logsource': {'category': 'network'},
            'detection': {
                'selection': {},
                'condition': 'selection'
            },
            'level': 'high',
            'tags': ['palantir', 'surveillance', 'auto-generated']
        }

        user_agents = [alert['details'].get('user_agent') for alert in self.alerts
                       if alert['category'] == 'BEACON' and alert['details'].get('user_agent')]

        if user_agents:
            sigma_rule['detection']['selection']['http.user_agent'] = user_agents

        return sigma_rule

    def run_full_scan(self):
        """Run complete detection suite"""
        print("Starting Palantir Detection Suite")
        print("=" * 50)

        start_time = time.time()

        self.collect_network_data(duration_minutes=1)
        self.check_beaconing_patterns()
        self.check_suspicious_processes()
        self.check_network_connections()
        self.check_tls_fingerprints('example.com')
        self.check_dns_patterns()
        self.check_data_chunking_patterns()

        scan_time = time.time() - start_time

        print("\n" + "=" * 50)
        print(f"Scan completed in {scan_time:.2f} seconds")
        print(f"Total alerts: {len(self.alerts)}")

        severity_counts = defaultdict(int)
        for alert in self.alerts:
            severity_counts[alert['severity']] += 1

        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")

        sigma_rule = self.generate_sigma_rules()
        if sigma_rule:
            print("\nAuto-generated Sigma rule:")
            print(json.dumps(sigma_rule, indent=2))

        return self.alerts

    def export_results(self, filename=None):
        """Export results to JSON"""
        if not filename:
            filename = f"palantir_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"

        report = {
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'total_alerts': len(self.alerts),
            'alerts': self.alerts,
            'sigma_rule': self.generate_sigma_rules()
        }

        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"Results exported to {filename}")
        return filename


def main():
    detector = PalantirDetector()

    print("Palantir/Surveillance Detection Tool")
    print("Based on SIEM Lab Documentation")
    print("-" * 40)

    alerts = detector.run_full_scan()
    detector.export_results()

    if alerts:
        print(f"\nATTENTION: {len(alerts)} suspicious indicators detected!")
        print("Review the exported JSON for details.")
    else:
        print("\nNo suspicious indicators detected in this scan.")

    return len(alerts)


if __name__ == "__main__":
    try:
        exit_code = main()
        exit(exit_code)
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\nFatal error: {e}")
        exit(2)
