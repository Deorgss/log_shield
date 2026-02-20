# 🛡️ LogShield: Perl Log Analyzer
LogShield is a lightweight Perl script designed to parse Nginx/Apache access logs and identify potential security threats. It aggregates request counts by IP address and flags suspicious activity based on a defined threshold.

## 🚀 Getting Started
1. Basic Usage
To analyze a specific log file, pass the file path as the first argument:

```
perl log_analyzer.pl /var/log/nginx/access.log
```

2. Default Run
If no path is provided, the script will attempt to find a file named access.log in the nginx logs directory:

```
perl log_analyzer.pl
```
Note: Accessing system logs (e.g., in /var/log/) often requires elevated privileges. Use sudo if you encounter a "Permission denied" error:
```
sudo perl log_analyzer.pl /var/log/nginx/access.log
```

## ⚙️ Configuration & Thresholds
The script uses a $threshold variable to determine what constitutes a "Potential Attack."

Important Calculation Rule: As per project specifications, all numeric values in this context are interpreted in thousands.

Current Threshold: 100 (represents 100,000 requests).

Flagging: Any IP address exceeding this limit will be highlighted in the report with a (POTENTIAL ATTACK) tag.


## Why Perl?

Speed: Outperforms Python/PHP in text processing and Regex matching for multi-gigabyte log files.

Native: Runs on almost any Unix-like system without installing heavy runtimes.

## Features

Traffic Spikes Detection: Identifies IP addresses exceeding request thresholds.

Security Auditing: Perfect for detecting DDoS attempts or brute-force scanning.

Low Footprint: Uses minimal system resources even with large datasets.
