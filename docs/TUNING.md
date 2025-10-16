# Tuning Guide - Gemini Exfil Detector

## Overview

This detector generates findings based on temporal correlation between Gemini "recon" actions and Drive "exfil" actions. Like any behavioral detection, it requires tuning to your environment.

## Severity Rubric

### High Severity
- **Criteria**: Recon followed by external share or export within ≤10 minutes
- **Examples**:
  - User asks Gemini to summarize a financial spreadsheet, then changes sharing to "anyone with link" 5 minutes later
  - User uses Gemini to analyze a document, then exports it to PDF 8 minutes later
- **Action**: Page on-call security team immediately

### Medium Severity
- **Criteria**: Recon followed by external share or export within 10-30 minutes
- **Examples**:
  - User asks Gemini about a document, then downloads it 15 minutes later
  - User summarizes a presentation, then copies it to an externally-shared folder 20 minutes later
- **Action**: Create ticket for next-day investigation

### Low Severity
- **Criteria**: Any correlation within 30-minute window
- **Examples**:
  - User asks Gemini about a file, then changes permissions to domain-wide 25 minutes later
  - User summarizes a document, then moves it to another folder 28 minutes later
- **Action**: Log for pattern analysis, no immediate action

## Tuning Parameters

### 1. Time Windows

**Default:**
```python
--window-minutes 30
```

**Tuning considerations:**
- **Shorter window (10-15 min)**: Higher precision, may miss slow-burn exfil
- **Longer window (60+ min)**: Catches delayed actions, but more false positives
- **Recommendation**: Start with 30 minutes, analyze false positive rate

**Advanced: Dual windows**
```python
# High severity: 0-10 min window
# Medium severity: 10-30 min window  
# Low severity: 30-60 min window
```

### 2. Recon Actions

**Current high-signal actions:**
```python
RECON_ACTIONS = {
    "ask_about_this_file",      # Direct file query
    "summarize_file",           # File summarization
    "analyze_documents",        # Multi-file analysis
    "report_unspecified_files", # Report generation
}
```

**Lower signal (may increase false positives):**
- `help_me_write` - Common in docs, less recon-focused
- `proofread` - Not reconnaissance
- `generate_images_in_product` - Not content analysis

**Tuning recommendation:**
- Start with the default high-signal set
- Add lower-signal actions only if you observe insider TTP evolution
- Review false positives monthly

### 3. Exfil Events

**High-risk events (immediate concern):**
```python
"change_visibility"      # Made public
"change_acl"            # External principal added
"export"                # Export to PDF/DOCX/CSV
"download"              # File download
```

**Medium-risk events (contextual):**
```python
"copy"                  # Could be benign or shadow share
"add_to_folder"         # Could move to external folder
```

**Tuning:**
- For high-security environments: Alert on all events
- For low false-positive tolerance: Remove `copy` and `add_to_folder`

### 4. Visibility Rules

**High-risk visibility values:**
```python
HIGH_RISK_VISIBILITY = {
    "people_with_link",        # Anyone with link
    "public_on_the_web",       # Publicly accessible
    "shared_externally",       # External domain
}
```

**Tuning for your org:**
```python
# If you share with partners frequently
ALLOWED_EXTERNAL_DOMAINS = ["partner-company.com"]

# If domain-wide sharing is normal
SUPPRESS_DOMAIN_SHARING = True
```

## Suppression Rules

### 1. Organizational Unit Suppressions

**Use case**: Security/IT teams legitimately investigate files

```json
{
  "suppressions": {
    "security_investigation_ous": [
      "/Security",
      "/IT/SecOps",
      "/Legal/eDiscovery"
    ]
  }
}
```

**When to suppress:**
- Actor in suppressed OU AND target file owner is outside that OU
- Example: Security analyst reviewing HR file (legitimate investigation)

**When NOT to suppress:**
- Internal sharing within same OU
- Downloads to personal devices
- Still log these for insider threat on the insider threat team

### 2. External Domain Allowlists

**Use case**: Regular business partners, M&A targets, contractors

```json
{
  "suppressions": {
    "allowed_external_domains": [
      "contractor-firm.com",
      "acquisition-target.com",
      "partner-company.com"
    ]
  }
}
```

**Best practices:**
- Review quarterly
- Require ticket/approval to add domains
- Auto-expire after 90 days unless renewed

### 3. Actor Suppressions

**Use case**: Service accounts, automated systems

```json
{
  "suppressions": {
    "exclude_actors": [
      "backup-service@your-domain.com",
      "automation@your-domain.com"
    ]
  }
}
```

**Warning**: Be extremely cautious suppressing human users

### 4. High-Risk Overrides

**Elevate severity for sensitive actors/data:**

```json
{
  "severity_overrides": {
    "high_risk_ous": [
      "/Executives",
      "/Finance",
      "/Research",
      "/Legal"
    ],
    "sensitive_labels": [
      "confidential",
      "restricted",
      "attorney-client-privilege"
    ]
  }
}
```

**Effect:**
- Finding involving high-risk OU actor → upgrade severity by 1 level
- Finding involving file with sensitive label → upgrade severity by 1 level
- Both → upgrade by 2 levels (low → high)

## Calibration Process

### Week 1: Observation Mode
1. Run detector with default settings
2. Export all findings (don't alert yet)
3. Review findings daily with security team
4. Tag each finding: true positive, false positive, benign pattern

### Week 2: Initial Tuning
1. Calculate false positive rate by severity
2. Add suppressions for common benign patterns
3. Adjust time window based on observed TTPs
4. Enable medium + high severity alerts

### Week 3-4: Refinement
1. Monitor alert volume and quality
2. Investigate all high severity findings
3. Add external domain allowlists as needed
4. Enable low severity logging (no alerts)

### Month 2+: Ongoing
1. Monthly review of all findings
2. Quarterly tuning session
3. Annual review of suppression rules
4. Update recon/exfil event sets based on Google API changes

## Metrics to Track

### Detection Quality
- **True Positive Rate**: Confirmed insider risk incidents / Total findings
- **False Positive Rate**: Benign findings / Total findings
- **Time to Detection**: Incident time → Finding time
- **Time to Response**: Finding time → Analyst review

### Operational
- **Alert Volume**: Findings per day/week
- **Alert Fatigue Score**: Alerts ignored/dismissed %
- **API Success Rate**: Successful fetches / Total attempts
- **Coverage**: Unique actors with Gemini activity / Total users

## Common False Positive Patterns

### Pattern 1: Legitimate Research
**Scenario**: Employee uses Gemini to summarize competitor docs, then shares with team
**Solution**: Suppress if source and destination are both internal

### Pattern 2: Presentation Prep
**Scenario**: User summarizes multiple docs with Gemini, then exports slides
**Solution**: Lower severity if export is to PPTX/DOCX (not PDF) and destination is internal

### Pattern 3: IT Support
**Scenario**: IT admin uses Gemini to understand a user's doc, then changes permissions
**Solution**: Suppress if actor in IT OU and target file is not high-sensitivity

### Pattern 4: Partner Collaboration
**Scenario**: Sales team summarizes proposals, shares with approved partners
**Solution**: Allowlist known partner domains

## Advanced Tuning

### Machine Learning Enrichment
After 90 days of data:
1. Export findings with labels (TP/FP)
2. Train a simple classifier (XGBoost, RandomForest)
3. Features: actor OU, file owner, time of day, day of week, exfil type
4. Use ML score as additional severity factor

### User Risk Scoring
Maintain a rolling 30-day risk score per user:
- +10 points per medium finding
- +25 points per high finding
- -5 points per week without findings
- Threshold: >50 = elevated risk user

### Context Enrichment
Correlate with:
- HR data (resignation date, PIP status, role changes)
- IT data (new device enrollment, VPN from new location)
- Physical security (badge swipes, off-hours access)

### Automated Response
For high-confidence patterns:
1. Auto-revoke public link (restore to domain-only)
2. Notify file owner
3. Require MFA re-auth for actor
4. Flag user for enhanced monitoring

## Support

For tuning assistance:
- Review documented findings in `examples/findings/`
- Check false positive wiki
- Contact security team for pattern discussion
