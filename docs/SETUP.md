# Setup Guide - Gemini Exfil Detector

## Prerequisites

- Python 3.9 or higher
- Google Workspace domain with Admin SDK API enabled
- Super Admin access to your Google Workspace domain
- Service account with domain-wide delegation

## Step 1: Create Service Account

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing project
3. Enable the **Admin SDK API**:
   - Navigate to APIs & Services > Library
   - Search for "Admin SDK API"
   - Click Enable

4. Create a service account:
   - Navigate to IAM & Admin > Service Accounts
   - Click "Create Service Account"
   - Name: `gemini-exfil-detector`
   - Description: `Service account for Gemini insider threat detection`
   - Click "Create and Continue"
   - Skip role assignment (not needed for domain-wide delegation)
   - Click "Done"

5. Create and download key:
   - Click on the newly created service account
   - Go to "Keys" tab
   - Click "Add Key" > "Create new key"
   - Choose JSON format
   - Save the file as `service-account.json`

6. Note the service account's **Client ID** (you'll need it for delegation)

## Step 2: Enable Domain-Wide Delegation

1. In the service account details, click "Show Advanced Settings"
2. Click "Enable Google Workspace Domain-wide Delegation"
3. Product name: `Gemini Exfil Detector`
4. Save

5. Go to [Google Workspace Admin Console](https://admin.google.com/)
6. Navigate to Security > Access and data control > API Controls
7. Click "Manage Domain Wide Delegation"
8. Click "Add new"
9. Enter the service account **Client ID**
10. Add OAuth Scope: `https://www.googleapis.com/auth/admin.reports.audit.readonly`
11. Click "Authorize"

## Step 3: Install the Detector

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/gemini-exfil-detector.git
cd gemini-exfil-detector

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Step 4: Configure

```bash
# Copy example config
cp config/config.example.json config/config.json

# Edit config with your details
nano config/config.json
```

Update the following fields:
- `service_account_path`: Path to your `service-account.json`
- `delegated_user`: Email of a super admin (e.g., `admin@your-domain.com`)
- `timezone`: Your organization's timezone
- `suppressions`: Customize allowed domains and OUs
- `alerting`: Configure webhook for your SIEM

## Step 5: Test

```bash
# Run a test detection (24-hour lookback)
python src/detector.py --config config/config.json --verbose

# Test with shorter lookback
python src/detector.py --config config/config.json --lookback-hours 6
```

## Step 6: Deploy

### Option A: Cron Job (Linux/macOS)

```bash
# Edit crontab
crontab -e

# Add entry to run every 10 minutes
*/10 * * * * /path/to/venv/bin/python /path/to/src/detector.py --config /path/to/config.json --lookback-hours 1 --output /var/log/gemini-exfil/findings.json 2>&1 | logger -t gemini-exfil
```

### Option B: Systemd Timer (Linux)

See `examples/systemd/` for service and timer unit files.

### Option C: Cloud Function (GCP)

See `examples/cloud-function/` for deployment package.

### Option D: Lambda (AWS)

See `examples/lambda/` for deployment package.

## Verification

After deploying, verify the detector is working:

1. Check logs for authentication success
2. Confirm events are being fetched (check log counts)
3. Test with a known pattern (create test file, use Gemini, then share it)
4. Verify findings are generated and sent to SIEM

## Troubleshooting

### Authentication Errors

```
google.auth.exceptions.GoogleAuthError: Unable to acquire delegation token
```

**Solution:**
- Verify service account has domain-wide delegation enabled
- Confirm the OAuth scope is authorized in Admin Console
- Ensure `delegated_user` is a super admin
- Check service account key is not expired

### No Events Found

```
INFO: Found 0 recon events
INFO: Found 0 exfil events
```

**Solution:**
- Gemini events only available from 2025-06-20 onwards
- Events have 180-day retention
- Verify users are actually using Gemini in your org
- Check `lookback_hours` isn't too far in the past

### API Quota Exceeded

```
HttpError 429: Rate Limit Exceeded
```

**Solution:**
- Increase time between detection runs
- Reduce `lookback_hours` to fetch fewer events
- Request quota increase in Google Cloud Console

## Security Best Practices

1. **Protect service account key**: Store in secrets manager (GCP Secret Manager, AWS Secrets Manager, HashiCorp Vault)
2. **Least privilege**: Service account only has audit log read access
3. **Rotate keys**: Rotate service account keys every 90 days
4. **Monitor the monitor**: Alert if detector stops running
5. **Audit access**: Log who can access the service account and config

## Next Steps

- Review [TUNING.md](TUNING.md) for severity calibration
- Configure alerting integration with your SIEM
- Set up automated response playbooks
- Review findings weekly to tune suppressions
