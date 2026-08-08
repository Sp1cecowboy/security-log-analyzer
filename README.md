Security Log Analyzer & Incident Detection Tool
A Python-based SOC/Blue Team tool designed to analyze web server logs (Nginx/Apache format) and automatically detect malicious traffic patterns and potential security incidents.

Key Features & Focus
Brute Force Detection: Flags IP addresses exceeding failed login attempt thresholds (HTTP 401).

Signature-based Threat Detection: Uses Regular Expressions (RegEx) to spot common web vulnerabilities like SQL Injection (SQLi) and Directory/Path Traversal.

Incident Response Ready: Generates structured security alerts for SOC analysts or SIEM integration.

Tech Stack
Language: Python 3

Libraries: Built-in modules (re, collections)

Concepts: Log Analysis, SIEM Logic, Pattern Matching, Web Security Basics

How to Run & Test
Clone or download the script:
git clone https://github.com/YOUR_USERNAME/security-log-analyzer.git

Run the analyzer:
python3 log_analyzer.py
