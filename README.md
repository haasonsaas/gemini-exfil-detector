# Gemini Exfil Detector

AI-Assisted Insider Threat Detection for Google Workspace

Detects when users leverage Gemini AI to analyze sensitive files ("recon") and then immediately share or exfiltrate them ("exfil")—a high-signal insider risk pattern.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

**Note:** This is released as a proof-of-concept detection. Test thoroughly in your environment before production deployment.

---

## What It Catches

The **LLM-aided "read-then-share" pattern** that insiders use to rapidly understand and move sensitive documents:

1. **Recon Step**: User invokes Gemini to summarize, analyze, or ask questions about a Drive file
2. **Exfil Step**: Within a short time window, the same user:
   - Changes file sharing to external/public
   - Downloads or exports the file  
   - Copies the file to an externally-shared folder
   - Modifies permissions to grant external access

This correlation produces a **high-signal insider-risk detector** without reading any user content.

### Advanced Detection Capabilities

**Multi-Stage Attack Detection**: Tracks cumulative reconnaissance activity with time-decay scoring to catch sophisticated insiders who wait days between recon and exfil (outside immediate correlation windows).

**File Sensitivity Context**: Enriches findings with file metadata (labels, ownership, sharing history) to prioritize high-sensitivity documents and reduce false positives.

**Intent Classification**: Uses behavioral analysis to distinguish malicious exfil from legitimate workflows:
- Destination domain reputation (partner vs unknown)
- Historical sharing patterns per user
- File ownership analysis
- Off-hours detection

---

## Why It Works

Traditional DLP focuses on content. This detector focuses on behavioral sequence:

- **Gemini logs** reveal intent (what files the user wanted to understand)
- **Drive audit logs** reveal action (what the user did with those files)
- **Temporal correlation** reveals insider TTP

You won't get Gemini prompt/response content, but you will get:

- Precise actions (`ask_about_this_file`, `summarize_file`, `catch_me_up`)
- App context (docs, drive, sheets, slides)
- Reliable timestamps (to the second)
- Actor email and file IDs

Google's documentation positions these logs for security telemetry:

> "Gemini in Workspace apps activities can help you understand how generative AI is being used in your organization, for compliance, security, and risk management."  
> — [Google Workspace Admin SDK](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gemini-in-workspace-apps)

---

## Detection Logic

### Immediate Correlation
```
IF user_action IN {ask_about_this_file, summarize_file, analyze_documents, ...}
   AND app_name IN {docs, drive, sheets, slides}
   AND (within 0-30 minutes)
   AND same_user performs {change_visibility, download, export, add_external_acl, ...}
THEN alert(severity = HIGH/MEDIUM/LOW)
```

### Multi-Stage Detection
```
IF user has cumulative_recon_score > 5.0 (decays with 48hr half-life)
   AND user performs exfil action
   EVEN IF outside immediate time window
THEN alert(severity = MEDIUM, "Delayed exfil after cumulative recon")
```

### Intent Classification
```
IF destination_domain IN trusted_partners
   OR user shares own_files frequently
   OR historical_pattern matches current_behavior
THEN suppress OR downgrade severity
```

### Severity Rubric

| Severity | Criteria | Example | Response |
|----------|----------|---------|----------|
| **High** | External share or export within ≤10 min | Gemini summarizes financial doc → exports to PDF 5 min later | Page on-call team |
| **Medium** | External share or export within 10-30 min | Gemini analyzes sheet → changes sharing to "anyone with link" 15 min later | Next-day investigation |
| **Low** | Any permission change within 30 min | Gemini asks about doc → moves to different folder 25 min later | Log for pattern analysis |

---

## Quick Start

### Prerequisites

- Python 3.9+
- Google Workspace domain with Admin SDK API enabled
- Service account with domain-wide delegation
- Super admin access

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/gemini-exfil-detector.git
cd gemini-exfil-detector

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp config/config.example.json config/config.json
# Edit config.json with your service account and delegated admin
```

### Basic Usage

```bash
# Run detection for last 24 hours
python src/detector.py --config config/config.json

# Run with 6-hour lookback
python src/detector.py --config config/config.json --lookback-hours 6

# Output findings to file
python src/detector.py --config config/config.json --output findings.json

# Verbose logging
python src/detector.py --config config/config.json --verbose
```

---

## Data Sources

### Gemini Events
- **API**: Admin SDK Reports API (`gemini_in_workspace_apps`)
- **Event**: `feature_utilization`
- **Available Since**: 2025-06-20
- **Retention**: 180 days (rolling)
- **Key Parameters**: `action`, `app_name`, `event_category`, `feature_source`

[📖 Full Gemini Event Schema](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gemini-in-workspace-apps)

### Drive Events
- **API**: Admin SDK Reports API (`drive`)
- **Events**: `download`, `export`, `copy`, `change_acl`, `change_visibility`, `add_to_folder`
- **Retention**: 180 days (rolling)
- **Key Parameters**: `doc_id`, `doc_title`, `visibility`, `new_value`, `old_value`, `owner`

[📖 Full Drive Event Schema](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/drive)

---

## Configuration

### Minimal Config

```json
{
  "service_account_path": "/path/to/service-account.json",
  "delegated_user": "admin@your-domain.com",
  "customer_id": "my_customer",
  "timezone": "America/Los_Angeles"
}
```

### Full Config with Advanced Features

```json
{
  "service_account_path": "/path/to/service-account.json",
  "delegated_user": "admin@your-domain.com",
  "customer_id": "my_customer",
  "timezone": "America/Los_Angeles",
  "redis_url": "redis://localhost:6379/0",
  "suppressions": {
    "allowed_external_domains": [
      "partner-company.com",
      "trusted-vendor.com"
    ],
    "security_investigation_ous": [
      "/Security",
      "/IT/SecOps"
    ],
    "exclude_actors": [
      "serviceaccount@your-domain.com"
    ]
  },
  "partner_domains": [
    "trusted-partner.com",
    "vendor-api.com"
  ],
  "high_risk_folders": [
    "1abc_exec_folder_id",
    "2def_finance_folder_id"
  ],
  "severity_overrides": {
    "high_risk_ous": [
      "/Executives",
      "/Finance",
      "/Research"
    ],
    "sensitive_labels": [
      "confidential",
      "restricted"
    ]
  },
  "alerting": {
    "webhook_url": "https://your-siem.com/webhooks/gemini-exfil",
    "alert_on_severities": ["high", "medium"]
  }
}
```

**New Configuration Options:**

- **`redis_url`** (optional): Redis connection for stateful recon tracking. If not provided, uses in-memory storage (not persistent across runs).
- **`partner_domains`**: Domains for known partners (reduces false positives but doesn't auto-suppress like `allowed_external_domains`).
- **`high_risk_folders`**: Drive folder IDs containing sensitive files for elevated severity.

---

## Setup Guide

### 1. Create Service Account

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Enable **Admin SDK API**
3. Create service account: `gemini-exfil-detector`
4. Generate JSON key
5. Note the **Client ID**

### 2. Enable Domain-Wide Delegation

1. In service account settings, enable Domain-Wide Delegation
2. Go to [Google Workspace Admin Console](https://admin.google.com/)
3. Navigate to **Security → API Controls → Domain-Wide Delegation**
4. Add Client ID with scopes:
   - `https://www.googleapis.com/auth/admin.reports.audit.readonly`
   - `https://www.googleapis.com/auth/drive.readonly` (for file context enrichment)

### 3. Deploy

Choose your deployment method:

- **Cron Job**: Run every 10 minutes via cron
- **Systemd Timer**: Use systemd on Linux
- **Cloud Function**: Deploy to GCP Cloud Functions
- **Lambda**: Deploy to AWS Lambda

**See [docs/SETUP.md](docs/SETUP.md) for detailed instructions.**

---

## Output Format

```json
[
  {
    "severity": "high",
    "actor": "user@your-domain.com",
    "exfil_event": "change_visibility",
    "exfil_time": "2025-01-15T14:23:45-08:00",
    "doc_id": "1abc...",
    "doc_title": "Q4 Financial Projections.xlsx",
    "recon_action": "summarize_file",
    "recon_time": "2025-01-15T14:18:12-08:00",
    "delta_minutes": 5.55,
    "visibility": "people_with_link",
    "reason": "External share within 10min of recon; High cumulative recon score (12.5)",
    "event_ids": {
      "recon": "gemini_evt_123",
      "exfil": "drive_evt_456"
    },
    "recon_score": 12.5,
    "file_context": {
      "sensitivity": "high",
      "labels": ["confidential", "finance"],
      "owner": "cfo@your-domain.com",
      "shared_externally_before": false
    },
    "intent_analysis": {
      "intent": "malicious",
      "confidence": 0.85,
      "reasons": [
        "Destination domain unknown-third-party.com is unknown/untrusted",
        "User is sharing someone else's file",
        "First-time share with unknown-third-party.com",
        "Activity occurred during off-hours"
      ],
      "should_suppress": false,
      "destination_domain": "unknown-third-party.com"
    }
  }
]
```

---

## Tuning

### Time Windows

```bash
# High-precision (fewer false positives)
python src/detector.py --config config.json --window-minutes 10

# Balanced (recommended)
python src/detector.py --config config.json --window-minutes 30

# High-recall (catches slow-burn exfil)
python src/detector.py --config config.json --window-minutes 60
```

### Recon Actions

**High-signal** (default):
- `ask_about_this_file` - Direct file query
- `summarize_file` - File summarization  
- `analyze_documents` - Multi-file analysis
- `catch_me_up` - Bulk triage

**Lower-signal** (may increase false positives):
- `help_me_write` - Content generation
- `proofread` - Grammar/spell check

### Suppression Rules

Add to config to reduce false positives:

```json
{
  "suppressions": {
    "security_investigation_ous": ["/Security"],
    "allowed_external_domains": ["partner.com"]
  }
}
```

**See [docs/TUNING.md](docs/TUNING.md) for comprehensive tuning guide.**

---

## Testing

Create a test scenario to verify detection:

1. **Create a test document** in Google Drive with sensitive-looking content
2. **Use Gemini** in Drive to ask "What is this document about?" or click "Summarize this file"
3. **Wait 2 minutes**
4. **Change sharing** to "Anyone with the link" or download the file
5. **Run detector**:
   ```bash
   python src/detector.py --config config.json --lookback-hours 1 --verbose
   ```
6. **Verify** a high-severity finding is generated

---

## Operational Metrics

Track these metrics for detector health:

- **True Positive Rate**: Confirmed insider incidents / Total findings
- **False Positive Rate**: Benign findings / Total findings  
- **Alert Volume**: Findings per day/week
- **API Success Rate**: Successful fetches / Total attempts
- **Coverage**: Unique actors with Gemini activity / Total users

---

## Built-In Advanced Features

### ✅ Multi-Stage Attack Detection
Tracks cumulative recon score with 48-hour decay half-life. Detects delayed exfil (Day 1: recon, Day 3: exfil).

### ✅ File Sensitivity Context
Enriches findings with file labels, ownership, and sharing history. Elevates severity for confidential files.

### ✅ Intent Classification
Behavioral analysis with domain reputation, user baselines, file ownership, and off-hours detection.

## Future Extensions

### 1. Bulk Recon + Mass Exfil
Detect `catch_me_up` on entire folders followed by multiple downloads within 1 hour.

### 2. Web Search → Exfil
Detect `search_web` feature usage (potential data leakage via web results) followed by sharing.

### 3. First-Ever Gemini Usage
Alert on first-time Gemini usage by admins or high-risk users followed by immediate sharing.

### 4. Context Mixing
Detect Gemini usage across multiple sensitive files from different OUs, suggesting reconnaissance.

---

## Security Best Practices

1. **Protect service account key**: Store in secrets manager (GCP Secret Manager, AWS Secrets Manager, HashiCorp Vault)
2. **Least privilege**: Service account only has `admin.reports.audit.readonly` scope
3. **Rotate keys**: Rotate service account keys every 90 days
4. **Monitor the monitor**: Alert if detector stops running
5. **Audit access**: Log who can access the service account and config

---

## Documentation

- [**Setup Guide**](docs/SETUP.md) - Detailed installation and deployment
- [**Tuning Guide**](docs/TUNING.md) - Calibration and false positive reduction
- [**API Reference**](https://developers.google.com/workspace/admin/reports/v1/reference/activities/list) - Google Admin SDK
- [**Gemini Events**](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gemini-in-workspace-apps) - Full event schema

---

## Contributing

Contributions welcome. Open an issue or pull request.

---

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- Google Workspace Admin SDK team for comprehensive audit logging
- Gemini team for exposing granular usage events

---

*This is released as a proof-of-concept. No warranty or support is provided.*
