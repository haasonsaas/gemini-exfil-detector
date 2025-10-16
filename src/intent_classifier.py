#!/usr/bin/env python3
"""
Intent Classifier - Reduce false positives through behavioral analysis

Classifies sharing intent to distinguish malicious exfil from legitimate workflows:
1. Destination domain reputation (partner vs unknown)
2. Historical sharing patterns per user
3. File ownership (own files vs others' files)
4. Temporal patterns (off-hours, weekends)
"""

import datetime as dt
import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set


@dataclass
class UserBaseline:
    actor: str
    typical_share_domains: Set[str]
    typical_share_count: int
    typical_download_count: int
    first_seen: dt.datetime
    last_updated: dt.datetime


class IntentClassifier:
    def __init__(self, config: Dict, admin_service: Any):
        self.config = config
        self.admin_service = admin_service
        self.logger = logging.getLogger(__name__)
        
        self.trusted_domains = set(config.get("suppressions", {}).get("allowed_external_domains", []))
        self.partner_domains = set(config.get("partner_domains", []))
        
        self.user_baselines: Dict[str, UserBaseline] = {}
        self.domain_reputation_cache: Dict[str, str] = {}

    def classify_intent(
        self,
        actor: str,
        exfil_event: str,
        doc_id: Optional[str],
        doc_owner: Optional[str],
        visibility: Optional[str],
        timestamp: dt.datetime,
        new_value: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Returns intent classification with confidence and reason.
        
        Returns:
            {
                "intent": "malicious" | "suspicious" | "legitimate",
                "confidence": 0.0-1.0,
                "reasons": List[str],
                "should_suppress": bool
            }
        """
        reasons = []
        confidence = 0.5
        should_suppress = False

        destination_domain = self._extract_destination_domain(new_value, visibility)
        
        if destination_domain:
            domain_reputation = self._get_domain_reputation(destination_domain)
            
            if domain_reputation == "trusted":
                reasons.append(f"Destination domain {destination_domain} is trusted")
                confidence -= 0.4
                should_suppress = True
            elif domain_reputation == "partner":
                reasons.append(f"Destination domain {destination_domain} is a known partner")
                confidence -= 0.2
            elif domain_reputation == "unknown":
                reasons.append(f"Destination domain {destination_domain} is unknown/untrusted")
                confidence += 0.3

        if doc_owner and actor:
            if self._normalize_email(doc_owner) == self._normalize_email(actor):
                reasons.append("User is sharing their own file")
                confidence -= 0.1
            else:
                reasons.append("User is sharing someone else's file")
                confidence += 0.3

        baseline = self._get_or_create_baseline(actor)
        if baseline:
            if destination_domain and destination_domain in baseline.typical_share_domains:
                reasons.append(f"User has historically shared with {destination_domain}")
                confidence -= 0.2
            elif destination_domain:
                reasons.append(f"First-time share with {destination_domain}")
                confidence += 0.2

        if self._is_off_hours(timestamp):
            reasons.append("Activity occurred during off-hours")
            confidence += 0.2
        
        if exfil_event in ["download", "export"]:
            if baseline and baseline.typical_download_count > 10:
                reasons.append("User frequently downloads files (likely legitimate workflow)")
                confidence -= 0.15

        if confidence >= 0.7:
            intent = "malicious"
        elif confidence >= 0.4:
            intent = "suspicious"
        else:
            intent = "legitimate"

        return {
            "intent": intent,
            "confidence": round(confidence, 2),
            "reasons": reasons,
            "should_suppress": should_suppress,
            "destination_domain": destination_domain,
        }

    def _extract_destination_domain(
        self, new_value: Optional[str], visibility: Optional[str]
    ) -> Optional[str]:
        if not new_value:
            return None

        if "@" in new_value:
            return new_value.split("@")[-1].strip()
        
        return None

    def _get_domain_reputation(self, domain: str) -> str:
        domain_lower = domain.lower()
        
        if domain_lower in self.domain_reputation_cache:
            return self.domain_reputation_cache[domain_lower]

        if domain_lower in self.trusted_domains:
            reputation = "trusted"
        elif domain_lower in self.partner_domains:
            reputation = "partner"
        else:
            reputation = "unknown"

        self.domain_reputation_cache[domain_lower] = reputation
        return reputation

    def _normalize_email(self, email: str) -> str:
        return email.lower().strip()

    def _get_or_create_baseline(self, actor: str) -> Optional[UserBaseline]:
        if actor in self.user_baselines:
            return self.user_baselines[actor]

        baseline = UserBaseline(
            actor=actor,
            typical_share_domains=set(),
            typical_share_count=0,
            typical_download_count=0,
            first_seen=dt.datetime.utcnow(),
            last_updated=dt.datetime.utcnow(),
        )
        self.user_baselines[actor] = baseline
        return baseline

    def update_baseline(
        self,
        actor: str,
        exfil_event: str,
        destination_domain: Optional[str],
    ) -> None:
        baseline = self._get_or_create_baseline(actor)
        
        if destination_domain:
            baseline.typical_share_domains.add(destination_domain)
            baseline.typical_share_count += 1
        
        if exfil_event in ["download", "export"]:
            baseline.typical_download_count += 1
        
        baseline.last_updated = dt.datetime.utcnow()

    def _is_off_hours(self, timestamp: dt.datetime) -> bool:
        hour = timestamp.hour
        weekday = timestamp.weekday()
        
        if weekday >= 5:
            return True
        
        if hour < 6 or hour > 20:
            return True
        
        return False

    def build_baselines_from_history(
        self,
        drive_events: List[Any],
        lookback_days: int = 30,
    ) -> None:
        """
        Build user baselines from historical Drive activity.
        This should be run periodically to keep baselines fresh.
        """
        self.logger.info(f"Building user baselines from {len(drive_events)} events")
        
        for event in drive_events:
            try:
                actor = event.actor
                exfil_event = event.event_name
                new_value = event.new_value
                
                destination_domain = self._extract_destination_domain(new_value, event.visibility)
                self.update_baseline(actor, exfil_event, destination_domain)
                
            except Exception as e:
                self.logger.warning(f"Error processing event for baseline: {e}")
                continue

        self.logger.info(f"Built baselines for {len(self.user_baselines)} users")
