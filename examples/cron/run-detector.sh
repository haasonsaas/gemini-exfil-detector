#!/bin/bash
# Cron wrapper script for Gemini Exfil Detector
# Add to crontab: */10 * * * * /path/to/run-detector.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV_PATH="$PROJECT_ROOT/venv"
CONFIG_PATH="$PROJECT_ROOT/config/config.json"
LOG_DIR="/var/log/gemini-exfil"
OUTPUT_DIR="/var/lib/gemini-exfil/findings"

mkdir -p "$LOG_DIR" "$OUTPUT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/detector_${TIMESTAMP}.log"
OUTPUT_FILE="$OUTPUT_DIR/findings_${TIMESTAMP}.json"

source "$VENV_PATH/bin/activate"

echo "[$(date)] Starting Gemini Exfil Detector" | tee -a "$LOG_FILE"

"$VENV_PATH/bin/python" "$PROJECT_ROOT/src/detector.py" \
    --config "$CONFIG_PATH" \
    --lookback-hours 1 \
    --window-minutes 30 \
    --output "$OUTPUT_FILE" \
    2>&1 | tee -a "$LOG_FILE"

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "[$(date)] Detection completed successfully" | tee -a "$LOG_FILE"
elif [ $EXIT_CODE -eq 1 ]; then
    echo "[$(date)] Detection completed with HIGH severity findings!" | tee -a "$LOG_FILE"
    # Optional: Send alert
    # curl -X POST https://your-webhook.com/alert -d @"$OUTPUT_FILE"
else
    echo "[$(date)] Detection failed with exit code $EXIT_CODE" | tee -a "$LOG_FILE"
    # Optional: Send error notification
fi

find "$LOG_DIR" -name "detector_*.log" -mtime +7 -delete
find "$OUTPUT_DIR" -name "findings_*.json" -mtime +30 -delete

exit $EXIT_CODE
