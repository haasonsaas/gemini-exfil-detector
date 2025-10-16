#!/usr/bin/env python3
"""
Burstiness Analyzer - Detect rapid reconnaissance patterns

Calculates burstiness metrics for recon sessions to identify suspicious
rapid-fire information gathering behavior.
"""

import datetime as dt
import logging
from typing import List
import statistics


class BurstinessAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def calculate_burstiness_score(
        self, timestamps: List[dt.datetime], action_count: int
    ) -> float:
        """
        Calculate burstiness score using inter-arrival coefficient of variation.
        Higher score = more bursty (suspicious)
        
        Returns: 0.0-10.0 score
        """
        if len(timestamps) < 2:
            return 0.0

        sorted_times = sorted(timestamps)
        inter_arrival_seconds = [
            (sorted_times[i + 1] - sorted_times[i]).total_seconds()
            for i in range(len(sorted_times) - 1)
        ]

        if not inter_arrival_seconds or all(t == 0 for t in inter_arrival_seconds):
            return 10.0

        mean_interval = statistics.mean(inter_arrival_seconds)
        
        if mean_interval == 0:
            return 10.0

        try:
            std_interval = statistics.stdev(inter_arrival_seconds)
            cv = std_interval / mean_interval
        except statistics.StatisticsError:
            cv = 0.0

        action_density = action_count / (max(inter_arrival_seconds) / 60.0) if max(inter_arrival_seconds) > 0 else action_count

        burstiness_score = min(10.0, (cv * 2.0) + (action_density * 0.5))

        return round(burstiness_score, 2)

    def is_burst_pattern(
        self, timestamps: List[dt.datetime], threshold: float = 6.0
    ) -> bool:
        """Check if activity pattern is bursty"""
        score = self.calculate_burstiness_score(timestamps, len(timestamps))
        return score >= threshold
