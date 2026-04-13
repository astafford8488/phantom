"""Anomaly detection engine — ML-based behavioral analysis.

Detection methods:
    - Isolation Forest for multivariate outlier detection
    - Statistical baselines (z-score, IQR) for metric anomalies
    - User & Entity Behavior Analytics (UEBA) profiling
"""

from __future__ import annotations

import hashlib
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from phantom.utils.logging import get_logger

logger = get_logger("anomaly")


@dataclass
class BehaviorProfile:
    """Behavioral baseline for a user or entity."""

    entity_id: str
    entity_type: str = "user"  # user, host, process
    event_counts: dict[str, int] = field(default_factory=dict)
    hourly_activity: list[int] = field(default_factory=lambda: [0] * 24)
    known_processes: set[str] = field(default_factory=set)
    known_destinations: set[str] = field(default_factory=set)
    login_sources: set[str] = field(default_factory=set)
    total_events: int = 0
    last_updated: float = field(default_factory=time.time)


@dataclass
class AnomalyScore:
    """Anomaly score for a single event."""

    score: float  # 0.0 (normal) to 1.0 (highly anomalous)
    method: str  # isolation_forest, statistical, ueba
    reasons: list[str] = field(default_factory=list)
    features: dict[str, float] = field(default_factory=dict)


class AnomalyDetector:
    """Multi-method anomaly detection engine.

    Combines Isolation Forest, statistical baselines, and UEBA
    to identify anomalous behavior in security events.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        zscore_threshold: float = 3.0,
        ueba_enabled: bool = True,
    ) -> None:
        self.contamination = contamination
        self.zscore_threshold = zscore_threshold
        self.ueba_enabled = ueba_enabled
        self._profiles: dict[str, BehaviorProfile] = {}
        self._iso_forest: Any = None
        self._feature_stats: dict[str, dict[str, float]] = {}

    def detect(self, events: list[dict[str, Any]]) -> list[Any]:
        """Run anomaly detection on normalized events.

        Returns list of DetectionResult objects for anomalous events.
        """
        from phantom.engine import DetectionResult

        if not events:
            return []

        results: list[DetectionResult] = []

        # Stage 1: Build feature matrix
        features = self._extract_features(events)

        # Stage 2: Isolation Forest
        iso_scores = self._isolation_forest_detect(features)

        # Stage 3: Statistical baselines
        stat_scores = self._statistical_detect(features)

        # Stage 4: UEBA profiling
        ueba_scores = self._ueba_detect(events) if self.ueba_enabled else [0.0] * len(events)

        # Combine scores and generate alerts
        for i, event in enumerate(events):
            iso = iso_scores[i] if i < len(iso_scores) else 0.0
            stat = stat_scores[i] if i < len(stat_scores) else 0.0
            ueba = ueba_scores[i] if i < len(ueba_scores) else 0.0

            # Weighted ensemble score
            combined = 0.4 * iso + 0.3 * stat + 0.3 * ueba

            if combined > 0.6:
                reasons = []
                if iso > 0.7:
                    reasons.append(f"Isolation Forest anomaly (score={iso:.2f})")
                if stat > 0.7:
                    reasons.append(f"Statistical outlier (score={stat:.2f})")
                if ueba > 0.7:
                    reasons.append(f"UEBA deviation (score={ueba:.2f})")

                severity = "critical" if combined > 0.9 else "high" if combined > 0.8 else "medium"

                results.append(DetectionResult(
                    rule_id=f"anomaly-{hashlib.md5(str(event).encode()).hexdigest()[:8]}",
                    rule_name=f"Anomaly: {', '.join(reasons[:2]) if reasons else 'Behavioral deviation'}",
                    severity=severity,
                    source="anomaly",
                    matched_events=[event],
                    confidence=min(combined, 1.0),
                    metadata={
                        "anomaly_score": combined,
                        "isolation_forest_score": iso,
                        "statistical_score": stat,
                        "ueba_score": ueba,
                        "reasons": reasons,
                        "features": features[i] if i < len(features) else {},
                    },
                ))

        logger.info("Anomaly detection complete", events=len(events), anomalies=len(results))
        return results

    def _extract_features(self, events: list[dict[str, Any]]) -> list[dict[str, float]]:
        """Extract numerical features from events for ML models."""
        features: list[dict[str, float]] = []

        for event in events:
            f: dict[str, float] = {}

            # Time-based features
            ts = event.get("timestamp", time.time())
            if isinstance(ts, (int, float)):
                import datetime
                dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
                f["hour"] = float(dt.hour)
                f["day_of_week"] = float(dt.weekday())
                f["is_weekend"] = 1.0 if dt.weekday() >= 5 else 0.0
                f["is_business_hours"] = 1.0 if 8 <= dt.hour <= 18 else 0.0

            # Command-line features
            cmd = str(event.get("command_line", ""))
            f["cmd_length"] = float(len(cmd))
            f["cmd_entropy"] = self._entropy(cmd)
            f["cmd_special_chars"] = float(sum(1 for c in cmd if not c.isalnum() and not c.isspace()))
            f["cmd_pipe_count"] = float(cmd.count("|"))
            f["cmd_semicolons"] = float(cmd.count(";"))
            f["has_encoded_cmd"] = 1.0 if any(x in cmd.lower() for x in ["-enc", "base64", "encodedcommand"]) else 0.0

            # Network features
            dst_port = event.get("dst_port")
            if dst_port is not None:
                try:
                    port = int(dst_port)
                    f["dst_port"] = float(port)
                    f["is_high_port"] = 1.0 if port > 1024 else 0.0
                    f["is_common_port"] = 1.0 if port in {22, 53, 80, 443, 445, 3389} else 0.0
                except (ValueError, TypeError):
                    pass

            # Process features
            process = str(event.get("process_name", ""))
            f["process_name_length"] = float(len(process))
            f["process_name_entropy"] = self._entropy(process)

            # Event metadata
            f["suspicious_cmd"] = 1.0 if event.get("suspicious_cmd") else 0.0

            features.append(f)

        return features

    def _isolation_forest_detect(self, features: list[dict[str, float]]) -> list[float]:
        """Run Isolation Forest anomaly detection."""
        if not features:
            return []

        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest

            # Build feature matrix (align all feature keys)
            all_keys = sorted(set().union(*(f.keys() for f in features)))
            matrix = np.array([
                [f.get(k, 0.0) for k in all_keys] for f in features
            ])

            if matrix.shape[0] < 10:
                # Too few samples — use statistical fallback
                return [0.5] * len(features)

            model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100,
            )
            model.fit(matrix)

            # score_samples returns negative values; more negative = more anomalous
            raw_scores = model.score_samples(matrix)

            # Normalize to 0-1 range (1 = most anomalous)
            min_s, max_s = raw_scores.min(), raw_scores.max()
            if max_s - min_s > 0:
                normalized = [(max_s - s) / (max_s - min_s) for s in raw_scores]
            else:
                normalized = [0.5] * len(raw_scores)

            return normalized

        except ImportError:
            logger.warning("scikit-learn not available, using statistical fallback")
            return self._statistical_detect(features)

    def _statistical_detect(self, features: list[dict[str, float]]) -> list[float]:
        """Statistical anomaly detection using z-scores."""
        if not features:
            return []

        # Compute per-feature statistics
        all_keys = sorted(set().union(*(f.keys() for f in features)))
        stats: dict[str, dict[str, float]] = {}

        for key in all_keys:
            values = [f.get(key, 0.0) for f in features]
            n = len(values)
            if n < 2:
                continue
            mean = sum(values) / n
            variance = sum((v - mean) ** 2 for v in values) / n
            std = math.sqrt(variance) if variance > 0 else 1.0
            stats[key] = {"mean": mean, "std": std}

        self._feature_stats = stats

        # Compute anomaly scores
        scores: list[float] = []
        for f in features:
            max_zscore = 0.0
            zscore_sum = 0.0
            count = 0

            for key in all_keys:
                if key not in stats:
                    continue
                value = f.get(key, 0.0)
                z = abs(value - stats[key]["mean"]) / stats[key]["std"]
                max_zscore = max(max_zscore, z)
                zscore_sum += z
                count += 1

            avg_zscore = zscore_sum / max(count, 1)

            # Score based on max z-score (0 to 1)
            score = min(max_zscore / (self.zscore_threshold * 2), 1.0)
            scores.append(score)

        return scores

    def _ueba_detect(self, events: list[dict[str, Any]]) -> list[float]:
        """User & Entity Behavior Analytics — profile deviation detection."""
        scores: list[float] = []

        # Build/update profiles
        for event in events:
            entity = event.get("username") or event.get("hostname") or "unknown"
            self._update_profile(entity, event)

        # Score against profiles
        for event in events:
            entity = event.get("username") or event.get("hostname") or "unknown"
            profile = self._profiles.get(entity)
            if not profile or profile.total_events < 5:
                scores.append(0.3)  # New entity — slight anomaly
                continue

            anomaly_signals: list[float] = []

            # Check unusual hour
            ts = event.get("timestamp", time.time())
            if isinstance(ts, (int, float)):
                import datetime
                dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
                hour = dt.hour
                total_hourly = sum(profile.hourly_activity)
                if total_hourly > 0:
                    expected_ratio = profile.hourly_activity[hour] / total_hourly
                    if expected_ratio < 0.01:
                        anomaly_signals.append(0.8)  # Activity in unusual hour
                    elif expected_ratio < 0.05:
                        anomaly_signals.append(0.4)

            # Check unknown process
            process = event.get("process_name", "")
            if process and profile.known_processes and process not in profile.known_processes:
                anomaly_signals.append(0.7)

            # Check unknown destination
            dst = event.get("dst_ip", "")
            if dst and profile.known_destinations and dst not in profile.known_destinations:
                anomaly_signals.append(0.6)

            # Check unknown login source
            src = event.get("src_ip", "")
            if src and profile.login_sources and src not in profile.login_sources:
                anomaly_signals.append(0.7)

            if anomaly_signals:
                scores.append(max(anomaly_signals))
            else:
                scores.append(0.1)

        return scores

    def _update_profile(self, entity_id: str, event: dict[str, Any]) -> None:
        """Update a behavioral profile with new event data."""
        if entity_id not in self._profiles:
            self._profiles[entity_id] = BehaviorProfile(entity_id=entity_id)

        profile = self._profiles[entity_id]
        profile.total_events += 1
        profile.last_updated = time.time()

        # Update hourly activity
        ts = event.get("timestamp", time.time())
        if isinstance(ts, (int, float)):
            import datetime
            dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
            profile.hourly_activity[dt.hour] += 1

        # Track known processes
        process = event.get("process_name", "")
        if process:
            profile.known_processes.add(process)

        # Track known destinations
        dst = event.get("dst_ip", "")
        if dst:
            profile.known_destinations.add(dst)

        # Track login sources
        src = event.get("src_ip", "")
        if src:
            profile.login_sources.add(src)

        # Track event type counts
        event_type = event.get("category", event.get("action", "unknown"))
        profile.event_counts[event_type] = profile.event_counts.get(event_type, 0) + 1

    @staticmethod
    def _entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        freq: dict[str, int] = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    def get_profile(self, entity_id: str) -> BehaviorProfile | None:
        """Get a behavioral profile by entity ID."""
        return self._profiles.get(entity_id)

    def list_profiles(self) -> list[dict[str, Any]]:
        """List all behavioral profiles with summary stats."""
        return [
            {
                "entity_id": p.entity_id,
                "entity_type": p.entity_type,
                "total_events": p.total_events,
                "known_processes": len(p.known_processes),
                "known_destinations": len(p.known_destinations),
            }
            for p in self._profiles.values()
        ]
