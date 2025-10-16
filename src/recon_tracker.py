#!/usr/bin/env python3
"""
Recon Tracker - Stateful reconnaissance activity tracking with decay

Tracks cumulative reconnaissance activity per user with time-based decay
to detect multi-stage attack chains that span beyond immediate correlation windows.

Architecture:
- Redis-backed persistence (with in-memory fallback)
- Exponential decay model (half-life based)
- Per-user recon scores
- File-level tracking when possible
"""

import datetime as dt
import json
import logging
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

DECAY_HALF_LIFE_HOURS = 48  # Score decays 50% every 48 hours
SCORE_THRESHOLD_HIGH = 10.0  # High-risk recon activity threshold
SCORE_THRESHOLD_MEDIUM = 5.0


@dataclass
class ReconActivity:
    actor: str
    timestamp: dt.datetime
    app: str
    action: str
    score: float
    doc_id: Optional[str] = None


class ReconTracker:
    def __init__(self, redis_url: Optional[str] = None, ttl_days: int = 14):
        self.logger = logging.getLogger(__name__)
        self.ttl_seconds = ttl_days * 24 * 60 * 60
        self.redis_client = None
        self.memory_store: Dict[str, List[Dict]] = {}

        if redis_url:
            try:
                import redis
                self.redis_client = redis.from_url(redis_url, decode_responses=True)
                self.redis_client.ping()
                self.logger.info(f"Connected to Redis for recon tracking")
            except ImportError:
                self.logger.warning("redis package not installed, using in-memory storage")
            except Exception as e:
                self.logger.warning(f"Redis connection failed: {e}, using in-memory storage")

    def _calculate_decay_factor(self, activity_time: dt.datetime, current_time: dt.datetime) -> float:
        hours_elapsed = (current_time - activity_time).total_seconds() / 3600
        return 0.5 ** (hours_elapsed / DECAY_HALF_LIFE_HOURS)

    def _action_to_score(self, action: str) -> float:
        """Convert recon action to base score"""
        high_signal_actions = {
            "ask_about_this_file": 3.0,
            "summarize_file": 3.0,
            "analyze_documents": 4.0,
            "catch_me_up": 5.0,
        }
        medium_signal_actions = {
            "summarize_long": 2.0,
            "ask_about_context": 2.0,
            "summarize": 1.5,
        }
        return high_signal_actions.get(action) or medium_signal_actions.get(action, 1.0)

    def record_recon(
        self,
        actor: str,
        timestamp: dt.datetime,
        app: str,
        action: str,
        doc_id: Optional[str] = None,
    ) -> None:
        base_score = self._action_to_score(action)
        activity = ReconActivity(
            actor=actor,
            timestamp=timestamp,
            app=app,
            action=action,
            score=base_score,
            doc_id=doc_id,
        )

        key = f"recon:{actor}"
        activity_data = asdict(activity)
        activity_data["timestamp"] = timestamp.isoformat()

        if self.redis_client:
            try:
                activities = self._get_redis_activities(key)
                activities.append(activity_data)
                self.redis_client.setex(
                    key, self.ttl_seconds, json.dumps(activities)
                )
            except Exception as e:
                self.logger.error(f"Failed to write to Redis: {e}")
                self._store_in_memory(key, activity_data)
        else:
            self._store_in_memory(key, activity_data)

    def _get_redis_activities(self, key: str) -> List[Dict]:
        try:
            data = self.redis_client.get(key)
            return json.loads(data) if data else []
        except Exception:
            return []

    def _store_in_memory(self, key: str, activity_data: Dict) -> None:
        if key not in self.memory_store:
            self.memory_store[key] = []
        self.memory_store[key].append(activity_data)

    def get_recon_score(self, actor: str, current_time: dt.datetime) -> float:
        key = f"recon:{actor}"
        activities = []

        if self.redis_client:
            try:
                activities = self._get_redis_activities(key)
            except Exception as e:
                self.logger.error(f"Failed to read from Redis: {e}")
                activities = self.memory_store.get(key, [])
        else:
            activities = self.memory_store.get(key, [])

        total_score = 0.0
        for activity_data in activities:
            try:
                activity_time = dt.datetime.fromisoformat(activity_data["timestamp"])
                base_score = activity_data["score"]
                decay_factor = self._calculate_decay_factor(activity_time, current_time)
                total_score += base_score * decay_factor
            except (KeyError, ValueError) as e:
                self.logger.warning(f"Malformed activity data: {e}")
                continue

        return round(total_score, 2)

    def get_recent_recon_files(
        self, actor: str, hours_back: int = 72
    ) -> List[str]:
        key = f"recon:{actor}"
        activities = []

        if self.redis_client:
            try:
                activities = self._get_redis_activities(key)
            except Exception:
                activities = self.memory_store.get(key, [])
        else:
            activities = self.memory_store.get(key, [])

        cutoff_time = dt.datetime.utcnow() - dt.timedelta(hours=hours_back)
        doc_ids = []

        for activity_data in activities:
            try:
                activity_time = dt.datetime.fromisoformat(activity_data["timestamp"])
                if activity_time >= cutoff_time and activity_data.get("doc_id"):
                    doc_ids.append(activity_data["doc_id"])
            except (KeyError, ValueError):
                continue

        return list(set(doc_ids))

    def get_risk_level(self, actor: str, current_time: dt.datetime) -> str:
        score = self.get_recon_score(actor, current_time)
        if score >= SCORE_THRESHOLD_HIGH:
            return "high"
        elif score >= SCORE_THRESHOLD_MEDIUM:
            return "medium"
        return "low"
