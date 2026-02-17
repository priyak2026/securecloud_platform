# SecureCloud Setup Guide

## Prerequisites

- AWS Account
- Python 3.9 or higher
- AWS CLI configured
- IAM permissions for CloudTrail and GuardDuty

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/priyak2026/securecloud-platform.git
cd securecloud-platform
```

### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure AWS Credentials
```bash
aws configure
```

Enter your:
- AWS Access Key ID
- AWS Secret Access Key  
- Default region (e.g., us-east-1)
- Default output format (json)

## AWS Services Setup

### Enable CloudTrail

1. Go to AWS Console → CloudTrail
2. Click "Create trail"
3. Name: `securecloud-audit-trail`
4. Create new S3 bucket for logs
5. Click "Create trail"

### Enable GuardDuty

1. Go to AWS Console → GuardDuty
2. Click "Get Started"
3. Click "Enable GuardDuty"
4. Wait 2-3 minutes for activation

## Usage

### CloudTrail Analyzer

Analyze CloudTrail logs for suspicious activity:
```bash
cd security-monitoring/threat-detector
python cloudtrail_analyzer.py
```

**Output:**
- Console: Real-time alerts and analysis summary
- File: `cloudtrail_security_report_YYYYMMDD_HHMMSS.txt`

### GuardDuty Monitor

Fetch and categorize GuardDuty findings:
```bash
cd security-monitoring/threat-detector
python guardduty_monitor.py
```

**Output:**
- Console: Findings summary by severity
- File: `guardduty_report_YYYYMMDD_HHMMSS.txt`

## Troubleshooting

### "No credentials found"

Run: `aws configure` and enter your AWS credentials

### "CloudTrail not enabled"

Enable CloudTrail in AWS Console (see setup instructions above)

### "GuardDuty detector not found"

Enable GuardDuty in AWS Console (see setup instructions above)

### "Access Denied" errors

Verify your IAM user has these permissions:
- `cloudtrail:LookupEvents`
- `cloudtrail:GetTrailStatus`
- `guardduty:ListDetectors`
- `guardduty:ListFindings`
- `guardduty:GetFindings`

## Project Structure
```
securecloud-platform/
├── README.md
├── requirements.txt
├── security-monitoring/
│   └── threat-detector/
│       ├── __init__.py
│       ├── cloudtrail_analyzer.py
│       └── guardduty_monitor.py
└── docs/
    └── SETUP.md
``
