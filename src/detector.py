#!/usr/bin/env python3
"""
Gemini Exfil Detector - AI-Assisted Insider Threat Detection for Google Workspace

Correlates Gemini activity (recon) with Drive audit events (exfil) to detect
insider risk patterns: LLM-assisted file analysis followed by sharing/exporting.

Architecture:
1. Fetch Gemini feature_utilization events (recon signals)
2. Fetch Drive audit events (permission changes, downloads, exports)
3. Correlate by actor and time window (0-30min for high severity)
4. Apply suppression rules and severity scoring
5. Emit findings to configured outputs

Documentation sources:
- Gemini events: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gemini-in-workspace-apps
- Admin SDK: https://developers.google.com/workspace/admin/reports/v1/reference/activities/list
- Drive events: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/drive
"""

import argparse
import datetime as dt
import json
import logging
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set

import pytz
from google.auth.exceptions import GoogleAuthError
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from file_context import FileContextEnricher
from intent_classifier import IntentClassifier
from recon_tracker import ReconTracker

VERSION = "1.0.0"

RECON_ACTIONS: Set[str] = {
    "ask_about_this_file",
    "summarize_file",
    "summarize_long",
    "summarize_proactive_short",
    "ask_about_context",
    "summarize",
    "catch_me_up",
    "ask_about_unspecified_file",
    "summarize_unspecified_file",
    "analyze_documents",
    "report_unspecified_files",
}

RECON_APPS: Set[str] = {"docs", "drive", "sheets", "slides"}

EXFIL_EVENT_PATTERNS: Set[str] = {
    "download",
    "export",
    "copy",
    "add_to_folder",
    "change_acl",
    "change_visibility",
    "deny_access_request",
    "request_access",
    "create_shortcut",
    "move",
    "publish_to_web",
    "transfer_ownership",
    "untrash",
}

HIGH_RISK_VISIBILITY: Set[str] = {
    "people_with_link",
    "public_on_the_web",
    "shared_externally",
}


@dataclass
class ReconEvent:
    actor: str
    timestamp: dt.datetime
    app: str
    action: str
    event_id: str


@dataclass
class ExfilEvent:
    actor: str
    timestamp: dt.datetime
    event_name: str
    doc_id: Optional[str]
    doc_title: Optional[str]
    visibility: Optional[str]
    old_visibility: Optional[str]
    new_value: Optional[str]
    old_value: Optional[str]
    owner: Optional[str]
    destination_folder_id: Optional[str]
    event_id: str
    ip_address: Optional[str] = None
    is_revert: bool = False


@dataclass
class Finding:
    severity: str
    actor: str
    exfil_event: str
    exfil_time: str
    doc_id: Optional[str]
    doc_title: Optional[str]
    recon_action: str
    recon_time: str
    delta_minutes: float
    visibility: Optional[str]
    reason: str
    event_ids: Dict[str, str]
    recon_score: Optional[float] = None
    file_context: Optional[Dict[str, Any]] = None
    intent_analysis: Optional[Dict[str, Any]] = None
    reason_codes: Optional[List[str]] = None
    ip_address: Optional[str] = None
    geo_anomaly: Optional[bool] = None


class GeminiExfilDetector:
    def __init__(
        self,
        service_account_path: str,
        delegated_user: str,
        customer_id: str = "my_customer",
        timezone: str = "UTC",
        config: Optional[Dict] = None,
    ):
        self.sa_path = service_account_path
        self.delegated_user = delegated_user
        self.customer_id = customer_id
        self.tz = pytz.timezone(timezone)
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self._service: Optional[Any] = None
        
        redis_url = self.config.get("redis_url")
        self.recon_tracker = ReconTracker(redis_url=redis_url)
        self.file_enricher: Optional[FileContextEnricher] = None
        self.intent_classifier: Optional[IntentClassifier] = None

    def _get_admin_service(self) -> Any:
        if self._service is None:
            try:
                scopes = [
                    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
                    "https://www.googleapis.com/auth/drive.readonly",
                ]
                creds = service_account.Credentials.from_service_account_file(
                    self.sa_path, scopes=scopes
                )
                creds = creds.with_subject(self.delegated_user)
                self._service = build(
                    "admin", "reports_v1", credentials=creds, cache_discovery=False
                )
                self.logger.info(
                    f"Authenticated as {self.delegated_user} via service account"
                )
                
                self.file_enricher = FileContextEnricher(self._service, self.config)
                self.intent_classifier = IntentClassifier(self.config, self._service)
                
            except GoogleAuthError as e:
                self.logger.error(f"Authentication failed: {e}")
                raise
            except Exception as e:
                self.logger.error(f"Failed to build admin service: {e}")
                raise
        return self._service

    def _list_activities(
        self,
        application_name: str,
        start_time: dt.datetime,
        end_time: Optional[dt.datetime] = None,
        event_name: Optional[str] = None,
        user_key: str = "all",
    ) -> Iterator[Dict[str, Any]]:
        service = self._get_admin_service()
        start_iso = start_time.replace(microsecond=0).isoformat() + "Z"
        params: Dict[str, Any] = {
            "userKey": user_key,
            "applicationName": application_name,
            "startTime": start_iso,
            "maxResults": 500,
        }
        if end_time:
            end_iso = end_time.replace(microsecond=0).isoformat() + "Z"
            params["endTime"] = end_iso
        if event_name:
            params["eventName"] = event_name

        try:
            request = service.activities().list(**params)
            while request is not None:
                response = request.execute()
                for item in response.get("items", []):
                    yield item
                request = service.activities().list_next(request, response)
        except HttpError as e:
            self.logger.error(
                f"HTTP error fetching {application_name} activities: {e}"
            )
            raise
        except Exception as e:
            self.logger.error(f"Error fetching {application_name} activities: {e}")
            raise

    def fetch_recon_events(
        self, start_time: dt.datetime, end_time: Optional[dt.datetime] = None
    ) -> List[ReconEvent]:
        self.logger.info(f"Fetching Gemini recon events from {start_time}")
        recon_events: List[ReconEvent] = []

        for activity in self._list_activities(
            "gemini_in_workspace_apps", start_time, end_time, "feature_utilization"
        ):
            try:
                actor = activity["actor"]["email"]
                timestamp = dt.datetime.fromisoformat(
                    activity["id"]["time"].replace("Z", "+00:00")
                )
                event_id = activity["id"].get("uniqueQualifier", "")

                for event in activity.get("events", []):
                    params = {
                        p["name"]: p.get("value")
                        for p in event.get("parameters", [])
                    }
                    action = params.get("action")
                    app_name = params.get("app_name")

                    if action in RECON_ACTIONS and app_name in RECON_APPS:
                        recon_event = ReconEvent(
                            actor=actor,
                            timestamp=timestamp,
                            app=app_name,
                            action=action,
                            event_id=event_id,
                        )
                        recon_events.append(recon_event)
                        
                        self.recon_tracker.record_recon(
                            actor=actor,
                            timestamp=timestamp,
                            app=app_name,
                            action=action,
                        )
                        
            except (KeyError, ValueError) as e:
                self.logger.warning(f"Malformed Gemini activity: {e}")
                continue

        self.logger.info(f"Found {len(recon_events)} recon events")
        return recon_events

    def fetch_exfil_events(
        self, start_time: dt.datetime, end_time: Optional[dt.datetime] = None
    ) -> List[ExfilEvent]:
        self.logger.info(f"Fetching Drive exfil events from {start_time}")
        exfil_events: List[ExfilEvent] = []

        for activity in self._list_activities("drive", start_time, end_time):
            try:
                actor = activity["actor"]["email"]
                timestamp = dt.datetime.fromisoformat(
                    activity["id"]["time"].replace("Z", "+00:00")
                )
                event_id = activity["id"].get("uniqueQualifier", "")
                ip_address = activity["id"].get("ipAddress")

                for event in activity.get("events", []):
                    event_name = event.get("name", "")

                    if any(pattern in event_name for pattern in EXFIL_EVENT_PATTERNS):
                        params = {
                            p["name"]: (
                                p.get("value")
                                or p.get("intValue")
                                or p.get("boolValue")
                            )
                            for p in event.get("parameters", [])
                        }

                        exfil_events.append(
                            ExfilEvent(
                                actor=actor,
                                timestamp=timestamp,
                                event_name=event_name,
                                doc_id=params.get("doc_id") or params.get("target_id"),
                                doc_title=params.get("doc_title"),
                                visibility=params.get("visibility"),
                                old_visibility=params.get("old_visibility"),
                                new_value=params.get("new_value"),
                                old_value=params.get("old_value"),
                                owner=params.get("owner"),
                                destination_folder_id=params.get(
                                    "destination_folder_id"
                                ),
                                event_id=event_id,
                                ip_address=ip_address,
                            )
                        )
            except (KeyError, ValueError) as e:
                self.logger.warning(f"Malformed Drive activity: {e}")
                continue

        self.logger.info(f"Found {len(exfil_events)} exfil events")
        
        exfil_events = self._detect_reverts(exfil_events)
        
        return exfil_events

    def correlate_events(
        self,
        recon_events: List[ReconEvent],
        exfil_events: List[ExfilEvent],
        window_minutes: int = 30,
    ) -> List[Finding]:
        self.logger.info(f"Correlating events with {window_minutes}min window")
        findings: List[Finding] = []

        recon_by_actor: Dict[str, List[ReconEvent]] = defaultdict(list)
        for recon in recon_events:
            recon_by_actor[recon.actor].append(recon)

        if self.intent_classifier:
            self.logger.info("Building user baselines from exfil events")
            self.intent_classifier.build_baselines_from_history(exfil_events)

        for exfil in exfil_events:
            recon_score = self.recon_tracker.get_recon_score(
                exfil.actor, exfil.timestamp
            )
            
            matched_recon = False
            for recon in recon_by_actor.get(exfil.actor, []):
                delta_seconds = (exfil.timestamp - recon.timestamp).total_seconds()
                delta_minutes = delta_seconds / 60.0

                if 0 <= delta_minutes <= window_minutes:
                    matched_recon = True
                    severity, reason, reason_codes = self._calculate_severity(exfil, delta_minutes, recon_score)

                    canary_docs = set(self.config.get("canary_doc_ids", []))
                    if exfil.doc_id and exfil.doc_id in canary_docs:
                        severity = "high"
                        reason = "CANARY DOCUMENT ACCESS - " + reason
                        reason_codes.append("canary_doc_access")
                    
                    finding = Finding(
                        severity=severity,
                        actor=exfil.actor,
                        exfil_event=exfil.event_name,
                        exfil_time=exfil.timestamp.astimezone(self.tz).isoformat(),
                        doc_id=exfil.doc_id,
                        doc_title=exfil.doc_title,
                        recon_action=recon.action,
                        recon_time=recon.timestamp.astimezone(self.tz).isoformat(),
                        delta_minutes=round(delta_minutes, 2),
                        visibility=exfil.visibility,
                        reason=reason,
                        event_ids={
                            "recon": recon.event_id,
                            "exfil": exfil.event_id,
                        },
                        recon_score=recon_score,
                        reason_codes=reason_codes,
                        ip_address=exfil.ip_address,
                    )
                    
                    finding_dict = asdict(finding)
                    
                    if self.file_enricher and exfil.doc_id:
                        finding_dict = self.file_enricher.enrich_finding(
                            finding_dict, exfil.doc_id
                        )
                    
                    if self.intent_classifier:
                        intent_analysis = self.intent_classifier.classify_intent(
                            actor=exfil.actor,
                            exfil_event=exfil.event_name,
                            doc_id=exfil.doc_id,
                            doc_owner=exfil.owner,
                            visibility=exfil.visibility,
                            timestamp=exfil.timestamp,
                            new_value=exfil.new_value,
                        )
                        finding_dict["intent_analysis"] = intent_analysis
                        
                        if intent_analysis["should_suppress"]:
                            self.logger.debug(
                                f"Suppressing finding for {exfil.actor}: {intent_analysis['reasons']}"
                            )
                            continue
                        
                        if intent_analysis["intent"] == "legitimate":
                            if finding_dict["severity"] == "high":
                                finding_dict["severity"] = "medium"
                            elif finding_dict["severity"] == "medium":
                                finding_dict["severity"] = "low"
                    
                    finding = Finding(**finding_dict)
                    findings.append(finding)
            
            if not matched_recon and recon_score > 5.0:
                self.logger.info(
                    f"Delayed exfil detected for {exfil.actor} (recon_score={recon_score})"
                )
                finding = Finding(
                    severity="medium",
                    actor=exfil.actor,
                    exfil_event=exfil.event_name,
                    exfil_time=exfil.timestamp.astimezone(self.tz).isoformat(),
                    doc_id=exfil.doc_id,
                    doc_title=exfil.doc_title,
                    recon_action="cumulative_recon",
                    recon_time="N/A (multi-stage)",
                    delta_minutes=0.0,
                    visibility=exfil.visibility,
                    reason=f"Delayed exfil after cumulative recon (score={recon_score})",
                    event_ids={"recon": "N/A", "exfil": exfil.event_id},
                    recon_score=recon_score,
                )
                findings.append(finding)

        self.logger.info(f"Generated {len(findings)} findings")
        return findings

    def _detect_reverts(self, exfil_events: List[ExfilEvent]) -> List[ExfilEvent]:
        """Detect revert-to-clean patterns: external share + rapid revert"""
        doc_visibility_changes: Dict[str, List[ExfilEvent]] = defaultdict(list)
        
        for event in exfil_events:
            if event.doc_id and "visibility" in event.event_name.lower():
                doc_visibility_changes[event.doc_id].append(event)
        
        for doc_id, changes in doc_visibility_changes.items():
            changes.sort(key=lambda e: e.timestamp)
            for i in range(len(changes) - 1):
                curr = changes[i]
                next_event = changes[i + 1]
                delta_minutes = (next_event.timestamp - curr.timestamp).total_seconds() / 60
                
                if delta_minutes <= 10:
                    curr_external = curr.visibility in HIGH_RISK_VISIBILITY
                    next_internal = next_event.visibility not in HIGH_RISK_VISIBILITY
                    
                    if curr_external and next_internal:
                        curr.is_revert = True
                        next_event.is_revert = True
        
        return exfil_events

    def _calculate_severity(
        self, exfil: ExfilEvent, delta_minutes: float, recon_score: float = 0.0
    ) -> tuple[str, str, List[str]]:
        reasons = []
        reason_codes = []

        is_external_share = (
            "change_acl" in exfil.event_name or "change_visibility" in exfil.event_name
        ) and exfil.visibility in HIGH_RISK_VISIBILITY

        is_export_download = "download" in exfil.event_name or "export" in exfil.event_name
        
        is_ownership_transfer = "transfer_ownership" in exfil.event_name
        is_shortcut = "create_shortcut" in exfil.event_name
        is_publish = "publish_to_web" in exfil.event_name

        if exfil.is_revert:
            reasons.append("External toggle with rapid revert (evasion pattern)")
            reason_codes.append("external_toggle_revert")
            severity = "high"
        elif delta_minutes <= 10:
            if is_external_share or is_ownership_transfer or is_publish:
                reasons.append("External share/transfer within 10min of recon")
                reason_codes.append("external_share_immediate")
                severity = "high"
            elif is_export_download:
                reasons.append("Export/download within 10min of recon")
                reason_codes.append("export_immediate")
                severity = "high"
            elif is_shortcut:
                reasons.append("Shortcut creation within 10min of recon")
                reason_codes.append("shortcut_immediate")
                severity = "medium"
            else:
                reasons.append("Activity within 10min")
                reason_codes.append("activity_immediate")
                severity = "medium"
        elif delta_minutes <= 30:
            if is_external_share or is_export_download or is_ownership_transfer:
                reasons.append("Suspicious activity within 30min")
                reason_codes.append("suspicious_30min")
                severity = "medium"
            else:
                reasons.append("Activity correlation detected")
                reason_codes.append("activity_correlated")
                severity = "low"
        else:
            reasons.append("Activity correlation detected")
            reason_codes.append("activity_correlated")
            severity = "low"

        if recon_score >= 10.0:
            reasons.append(f"High cumulative recon score ({recon_score})")
            reason_codes.append("high_recon_score")
            if severity == "medium":
                severity = "high"
            elif severity == "low":
                severity = "medium"
        elif recon_score >= 5.0:
            reasons.append(f"Elevated recon score ({recon_score})")
            reason_codes.append("elevated_recon_score")

        return severity, "; ".join(reasons), reason_codes


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Gemini Exfil Detector - AI-Assisted Insider Threat Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run detection for last 24 hours
  %(prog)s --config config.json

  # Run with 6-hour lookback
  %(prog)s --config config.json --lookback-hours 6

  # Output JSON to file
  %(prog)s --config config.json --output findings.json

  # Verbose logging
  %(prog)s --config config.json --verbose
        """,
    )

    parser.add_argument(
        "--config",
        required=True,
        type=Path,
        help="Path to configuration JSON file",
    )
    parser.add_argument(
        "--lookback-hours",
        type=int,
        default=24,
        help="Hours to look back for events (default: 24)",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=30,
        help="Correlation window in minutes (default: 30)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file for findings (JSON format)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    args = parser.parse_args()

    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    try:
        with open(args.config) as f:
            config = json.load(f)

        detector = GeminiExfilDetector(
            service_account_path=config["service_account_path"],
            delegated_user=config["delegated_user"],
            customer_id=config.get("customer_id", "my_customer"),
            timezone=config.get("timezone", "UTC"),
            config=config,
        )

        now = dt.datetime.utcnow()
        start_time = now - dt.timedelta(hours=args.lookback_hours)

        logger.info(f"Starting detection run (lookback: {args.lookback_hours}h)")

        recon_events = detector.fetch_recon_events(start_time)
        exfil_events = detector.fetch_exfil_events(start_time)

        findings = detector.correlate_events(
            recon_events, exfil_events, args.window_minutes
        )

        findings_sorted = sorted(
            findings,
            key=lambda f: (
                {"high": 0, "medium": 1, "low": 2}.get(f.severity, 3),
                f.exfil_time,
            ),
        )

        findings_dict = [asdict(f) for f in findings_sorted]

        if args.output:
            with open(args.output, "w") as f:
                json.dump(findings_dict, f, indent=2)
            logger.info(f"Findings written to {args.output}")
        else:
            print(json.dumps(findings_dict, indent=2))

        high_count = sum(1 for f in findings if f.severity == "high")
        medium_count = sum(1 for f in findings if f.severity == "medium")
        low_count = sum(1 for f in findings if f.severity == "low")

        logger.info(
            f"Detection complete: {high_count} high, {medium_count} medium, {low_count} low severity findings"
        )

        return 0 if high_count == 0 else 1

    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return 2
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in config file: {e}")
        return 2
    except GoogleAuthError as e:
        logger.error(f"Authentication error: {e}")
        return 3
    except HttpError as e:
        logger.error(f"Google API error: {e}")
        return 3
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return 4


if __name__ == "__main__":
    sys.exit(main())
