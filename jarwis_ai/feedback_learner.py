"""
Jarwis Feedback Learner - Self-Improving Pattern Weights
==========================================================

Records user feedback on findings (confirmed/false_positive) and
adjusts pattern weights using Bayesian updating to improve accuracy
over time.

Features:
- Bayesian weight updates from feedback
- Pattern effectiveness tracking
- Scanner accuracy per target type
- Historical learning data storage

Author: Jarwis AI Team
Created: January 2026
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from enum import Enum
import logging
import math

logger = logging.getLogger(__name__)


class FeedbackType(Enum):
    """Types of user feedback"""
    CONFIRMED = "confirmed"           # User confirmed finding is valid
    FALSE_POSITIVE = "false_positive" # User marked as false positive
    NEEDS_REVIEW = "needs_review"     # Uncertain, needs more review
    EXPLOITED = "exploited"           # User successfully exploited it


class LearningEventType(Enum):
    """Types of learning events"""
    USER_FEEDBACK = "user_feedback"
    SCAN_RESULT = "scan_result"
    PATTERN_UPDATE = "pattern_update"
    SCANNER_METRIC = "scanner_metric"


@dataclass
class FeedbackEvent:
    """A user feedback event"""
    event_id: str
    timestamp: datetime
    
    # What was the feedback about
    finding_id: str
    scan_id: str
    feedback_type: FeedbackType
    
    # Context
    pattern_ids: List[str]  # Patterns that matched
    scanner_id: str
    target_type: str  # e-commerce, api, saas, etc.
    target_domain: str
    
    # Finding details
    vuln_type: str
    original_severity: str
    original_confidence: float
    
    # User info
    user_id: Optional[str] = None
    user_note: Optional[str] = None


@dataclass
class PatternStats:
    """Statistics for a single pattern"""
    pattern_id: str
    
    # Counts
    total_matches: int = 0
    true_positive_count: int = 0
    false_positive_count: int = 0
    unreviewed_count: int = 0
    
    # Calculated metrics
    accuracy_rate: float = 0.5  # TP / (TP + FP)
    confidence_adjustment: float = 0.0  # -0.5 to +0.5
    
    # By target type
    accuracy_by_target: Dict[str, float] = field(default_factory=dict)
    
    # Temporal
    last_updated: datetime = field(default_factory=datetime.utcnow)
    trend: str = "stable"  # improving, declining, stable


@dataclass
class ScannerStats:
    """Statistics for a scanner module"""
    scanner_id: str
    
    # Overall metrics
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    
    # Accuracy
    overall_accuracy: float = 0.5
    accuracy_by_target: Dict[str, float] = field(default_factory=dict)
    
    # Effectiveness
    high_severity_ratio: float = 0.0  # % of findings that are high/critical
    actionable_ratio: float = 0.0  # % of findings user took action on
    
    last_updated: datetime = field(default_factory=datetime.utcnow)


@dataclass
class LearningSnapshot:
    """Snapshot of learning state for analysis"""
    timestamp: datetime
    total_feedback_events: int
    pattern_stats: Dict[str, PatternStats]
    scanner_stats: Dict[str, ScannerStats]
    overall_accuracy: float
    trend: str


class FeedbackLearner:
    """
    Self-Improving Learning Engine
    
    Records user feedback and updates pattern weights using
    Bayesian inference to improve detection accuracy over time.
    """
    
    # Learning rate controls how quickly weights adapt
    DEFAULT_LEARNING_RATE = 0.1
    
    # Minimum samples before weight adjustments
    MIN_SAMPLES_FOR_ADJUSTMENT = 5
    
    # Weight bounds
    MIN_WEIGHT_ADJUSTMENT = -0.5
    MAX_WEIGHT_ADJUSTMENT = 0.5
    
    def __init__(
        self,
        db_session=None,
        learning_rate: float = None,
        pattern_matcher=None
    ):
        """
        Initialize the feedback learner
        
        Args:
            db_session: Database session for persisting learning data
            learning_rate: How quickly to adapt (0.01-0.5)
            pattern_matcher: PatternMatcher instance to update
        """
        self.db_session = db_session
        self.learning_rate = learning_rate or self.DEFAULT_LEARNING_RATE
        self.pattern_matcher = pattern_matcher
        
        # In-memory caches (persisted to DB periodically)
        self.feedback_events: List[FeedbackEvent] = []
        self.pattern_stats: Dict[str, PatternStats] = {}
        self.scanner_stats: Dict[str, ScannerStats] = {}
        
        # Load existing learning data
        self._load_learning_data()
    
    def _load_learning_data(self):
        """Load existing learning data from database"""
        if not self.db_session:
            return
        
        try:
            # Query PatternKnowledge table for learned weights
            # This will be implemented when database migration is done
            logger.info("Loading learning data from database...")
        except Exception as e:
            logger.warning(f"Could not load learning data: {e}")
    
    async def record_feedback(
        self,
        finding_id: str,
        scan_id: str,
        feedback_type: FeedbackType,
        pattern_ids: List[str],
        scanner_id: str,
        vuln_type: str,
        original_severity: str,
        original_confidence: float,
        target_type: str = "unknown",
        target_domain: str = "",
        user_id: Optional[str] = None,
        user_note: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Record user feedback on a finding
        
        Args:
            finding_id: ID of the finding
            scan_id: ID of the scan
            feedback_type: Type of feedback
            pattern_ids: Patterns that matched this finding
            scanner_id: Scanner that found it
            vuln_type: Type of vulnerability
            original_severity: Original severity
            original_confidence: Original confidence score
            target_type: Type of target (e-commerce, api, etc.)
            target_domain: Target domain
            user_id: User providing feedback
            user_note: Optional note from user
            
        Returns:
            Dict with learning update results
        """
        import uuid
        
        event = FeedbackEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            finding_id=finding_id,
            scan_id=scan_id,
            feedback_type=feedback_type,
            pattern_ids=pattern_ids,
            scanner_id=scanner_id,
            target_type=target_type,
            target_domain=target_domain,
            vuln_type=vuln_type,
            original_severity=original_severity,
            original_confidence=original_confidence,
            user_id=user_id,
            user_note=user_note
        )
        
        self.feedback_events.append(event)
        
        # Update pattern stats
        pattern_updates = self._update_pattern_stats(event)
        
        # Update scanner stats
        scanner_update = self._update_scanner_stats(event)
        
        # Apply weight adjustments
        weight_adjustments = self._apply_weight_adjustments(event)
        
        # Persist to database
        await self._persist_feedback(event)
        
        return {
            "event_id": event.event_id,
            "pattern_updates": pattern_updates,
            "scanner_update": scanner_update,
            "weight_adjustments": weight_adjustments,
            "feedback_type": feedback_type.value
        }
    
    def _update_pattern_stats(self, event: FeedbackEvent) -> List[Dict[str, Any]]:
        """Update statistics for patterns involved in this finding"""
        updates = []
        
        is_true_positive = event.feedback_type in [
            FeedbackType.CONFIRMED, 
            FeedbackType.EXPLOITED
        ]
        is_false_positive = event.feedback_type == FeedbackType.FALSE_POSITIVE
        
        for pattern_id in event.pattern_ids:
            if pattern_id not in self.pattern_stats:
                self.pattern_stats[pattern_id] = PatternStats(pattern_id=pattern_id)
            
            stats = self.pattern_stats[pattern_id]
            stats.total_matches += 1
            
            if is_true_positive:
                stats.true_positive_count += 1
            elif is_false_positive:
                stats.false_positive_count += 1
            else:
                stats.unreviewed_count += 1
            
            # Recalculate accuracy
            reviewed = stats.true_positive_count + stats.false_positive_count
            if reviewed > 0:
                stats.accuracy_rate = stats.true_positive_count / reviewed
            
            # Update accuracy by target type
            target_type = event.target_type
            if target_type not in stats.accuracy_by_target:
                stats.accuracy_by_target[target_type] = 0.5
            
            # Moving average for target-specific accuracy
            current = stats.accuracy_by_target[target_type]
            new_value = 1.0 if is_true_positive else (0.0 if is_false_positive else current)
            stats.accuracy_by_target[target_type] = current * 0.9 + new_value * 0.1
            
            # Calculate confidence adjustment using Bayesian update
            stats.confidence_adjustment = self._calculate_confidence_adjustment(stats)
            
            # Determine trend
            stats.trend = self._determine_trend(stats)
            stats.last_updated = datetime.utcnow()
            
            updates.append({
                "pattern_id": pattern_id,
                "accuracy_rate": round(stats.accuracy_rate, 3),
                "confidence_adjustment": round(stats.confidence_adjustment, 3),
                "trend": stats.trend
            })
        
        return updates
    
    def _calculate_confidence_adjustment(self, stats: PatternStats) -> float:
        """
        Calculate confidence adjustment using Bayesian updating
        
        Uses: adjustment = learning_rate * (accuracy - 0.5)
        
        If accuracy > 0.5, increase confidence
        If accuracy < 0.5, decrease confidence
        """
        reviewed = stats.true_positive_count + stats.false_positive_count
        
        if reviewed < self.MIN_SAMPLES_FOR_ADJUSTMENT:
            return 0.0  # Not enough data
        
        # Bayesian update with prior
        prior = 0.5  # Assume 50% accuracy initially
        likelihood = stats.accuracy_rate
        
        # Weighted by sample size (more samples = more confidence in update)
        sample_weight = min(1.0, reviewed / 50)  # Max confidence at 50 samples
        
        # Adjustment magnitude
        adjustment = (likelihood - prior) * sample_weight * self.learning_rate * 2
        
        # Bound the adjustment
        return max(
            self.MIN_WEIGHT_ADJUSTMENT,
            min(self.MAX_WEIGHT_ADJUSTMENT, adjustment)
        )
    
    def _determine_trend(self, stats: PatternStats) -> str:
        """Determine if pattern accuracy is improving, declining, or stable"""
        reviewed = stats.true_positive_count + stats.false_positive_count
        
        if reviewed < 10:
            return "stable"  # Not enough data
        
        # Look at recent vs overall
        # For now, use simple threshold
        if stats.accuracy_rate > 0.7:
            return "improving"
        elif stats.accuracy_rate < 0.3:
            return "declining"
        else:
            return "stable"
    
    def _update_scanner_stats(self, event: FeedbackEvent) -> Dict[str, Any]:
        """Update statistics for the scanner that produced this finding"""
        scanner_id = event.scanner_id
        
        if scanner_id not in self.scanner_stats:
            self.scanner_stats[scanner_id] = ScannerStats(scanner_id=scanner_id)
        
        stats = self.scanner_stats[scanner_id]
        stats.total_findings += 1
        
        is_true_positive = event.feedback_type in [
            FeedbackType.CONFIRMED,
            FeedbackType.EXPLOITED
        ]
        is_false_positive = event.feedback_type == FeedbackType.FALSE_POSITIVE
        
        if is_true_positive:
            stats.true_positives += 1
        elif is_false_positive:
            stats.false_positives += 1
        
        # Recalculate overall accuracy
        reviewed = stats.true_positives + stats.false_positives
        if reviewed > 0:
            stats.overall_accuracy = stats.true_positives / reviewed
        
        # Update accuracy by target type
        target_type = event.target_type
        if target_type not in stats.accuracy_by_target:
            stats.accuracy_by_target[target_type] = 0.5
        
        current = stats.accuracy_by_target[target_type]
        new_value = 1.0 if is_true_positive else (0.0 if is_false_positive else current)
        stats.accuracy_by_target[target_type] = current * 0.9 + new_value * 0.1
        
        # Update severity ratio
        if event.original_severity in ["critical", "high"]:
            stats.high_severity_ratio = (
                stats.high_severity_ratio * 0.95 + 0.05
            )
        else:
            stats.high_severity_ratio = stats.high_severity_ratio * 0.95
        
        # Actionable ratio (user took action = confirmed or exploited or false positive)
        if event.feedback_type != FeedbackType.NEEDS_REVIEW:
            stats.actionable_ratio = stats.actionable_ratio * 0.95 + 0.05
        else:
            stats.actionable_ratio = stats.actionable_ratio * 0.95
        
        stats.last_updated = datetime.utcnow()
        
        return {
            "scanner_id": scanner_id,
            "overall_accuracy": round(stats.overall_accuracy, 3),
            "total_findings": stats.total_findings,
            "high_severity_ratio": round(stats.high_severity_ratio, 3)
        }
    
    def _apply_weight_adjustments(self, event: FeedbackEvent) -> List[Dict[str, Any]]:
        """Apply learned weight adjustments to pattern matcher"""
        adjustments = []
        
        if not self.pattern_matcher:
            return adjustments
        
        is_true_positive = event.feedback_type in [
            FeedbackType.CONFIRMED,
            FeedbackType.EXPLOITED
        ]
        
        for pattern_id in event.pattern_ids:
            try:
                self.pattern_matcher.update_pattern_weight(
                    pattern_id=pattern_id,
                    is_true_positive=is_true_positive,
                    learning_rate=self.learning_rate
                )
                
                pattern = self.pattern_matcher.get_pattern_by_id(pattern_id)
                if pattern:
                    adjustments.append({
                        "pattern_id": pattern_id,
                        "new_weight": round(pattern.effective_weight, 3),
                        "accuracy": round(pattern.accuracy_rate, 3)
                    })
            except Exception as e:
                logger.error(f"Failed to update pattern weight {pattern_id}: {e}")
        
        return adjustments
    
    async def _persist_feedback(self, event: FeedbackEvent):
        """Persist feedback event to database"""
        if not self.db_session:
            return
        
        try:
            # Save to LearningEvent table (will be created with migration)
            # For now, just log
            logger.info(
                f"Recorded feedback: {event.feedback_type.value} for finding {event.finding_id}"
            )
        except Exception as e:
            logger.error(f"Failed to persist feedback: {e}")
    
    def get_pattern_recommendation(
        self,
        target_type: str
    ) -> List[Tuple[str, float]]:
        """
        Get pattern recommendations for a target type
        
        Args:
            target_type: Type of target (e-commerce, api, etc.)
            
        Returns:
            List of (pattern_id, effectiveness_score) tuples
        """
        recommendations = []
        
        for pattern_id, stats in self.pattern_stats.items():
            # Get target-specific accuracy or fall back to overall
            accuracy = stats.accuracy_by_target.get(
                target_type, 
                stats.accuracy_rate
            )
            
            # Weight by sample size
            reviewed = stats.true_positive_count + stats.false_positive_count
            sample_confidence = min(1.0, reviewed / 20)
            
            # Effectiveness = accuracy * sample_confidence
            effectiveness = accuracy * sample_confidence
            
            recommendations.append((pattern_id, effectiveness))
        
        # Sort by effectiveness
        recommendations.sort(key=lambda x: x[1], reverse=True)
        
        return recommendations
    
    def get_scanner_recommendation(
        self,
        target_type: str
    ) -> List[Tuple[str, float]]:
        """
        Get scanner recommendations for a target type
        
        Args:
            target_type: Type of target
            
        Returns:
            List of (scanner_id, effectiveness_score) tuples
        """
        recommendations = []
        
        for scanner_id, stats in self.scanner_stats.items():
            # Get target-specific accuracy
            accuracy = stats.accuracy_by_target.get(
                target_type,
                stats.overall_accuracy
            )
            
            # Weight by actionability and severity
            effectiveness = (
                accuracy * 0.5 +
                stats.actionable_ratio * 0.3 +
                stats.high_severity_ratio * 0.2
            )
            
            recommendations.append((scanner_id, effectiveness))
        
        recommendations.sort(key=lambda x: x[1], reverse=True)
        
        return recommendations
    
    def get_learning_snapshot(self) -> LearningSnapshot:
        """Get current learning state snapshot"""
        total_events = len(self.feedback_events)
        
        # Calculate overall accuracy
        total_reviewed = 0
        total_tp = 0
        
        for stats in self.pattern_stats.values():
            total_reviewed += stats.true_positive_count + stats.false_positive_count
            total_tp += stats.true_positive_count
        
        overall_accuracy = total_tp / total_reviewed if total_reviewed > 0 else 0.5
        
        # Determine overall trend
        improving = sum(1 for s in self.pattern_stats.values() if s.trend == "improving")
        declining = sum(1 for s in self.pattern_stats.values() if s.trend == "declining")
        
        if improving > declining * 2:
            trend = "improving"
        elif declining > improving * 2:
            trend = "declining"
        else:
            trend = "stable"
        
        return LearningSnapshot(
            timestamp=datetime.utcnow(),
            total_feedback_events=total_events,
            pattern_stats=self.pattern_stats.copy(),
            scanner_stats=self.scanner_stats.copy(),
            overall_accuracy=round(overall_accuracy, 3),
            trend=trend
        )
    
    def get_improvement_suggestions(self) -> List[Dict[str, Any]]:
        """Get suggestions for improving scan accuracy"""
        suggestions = []
        
        # Find patterns with low accuracy
        for pattern_id, stats in self.pattern_stats.items():
            reviewed = stats.true_positive_count + stats.false_positive_count
            
            if reviewed >= 10 and stats.accuracy_rate < 0.3:
                suggestions.append({
                    "type": "disable_pattern",
                    "pattern_id": pattern_id,
                    "reason": f"Low accuracy ({stats.accuracy_rate:.0%})",
                    "impact": "Reduce false positives",
                    "priority": "high" if stats.accuracy_rate < 0.2 else "medium"
                })
        
        # Find scanners with low accuracy for specific targets
        for scanner_id, stats in self.scanner_stats.items():
            for target_type, accuracy in stats.accuracy_by_target.items():
                if accuracy < 0.4 and stats.total_findings > 10:
                    suggestions.append({
                        "type": "skip_scanner_for_target",
                        "scanner_id": scanner_id,
                        "target_type": target_type,
                        "reason": f"Low accuracy ({accuracy:.0%}) for {target_type}",
                        "impact": "Faster scans, fewer false positives",
                        "priority": "medium"
                    })
        
        # Find patterns that are highly effective
        for pattern_id, stats in self.pattern_stats.items():
            reviewed = stats.true_positive_count + stats.false_positive_count
            
            if reviewed >= 10 and stats.accuracy_rate > 0.9:
                suggestions.append({
                    "type": "boost_pattern",
                    "pattern_id": pattern_id,
                    "reason": f"High accuracy ({stats.accuracy_rate:.0%})",
                    "impact": "Prioritize this pattern",
                    "priority": "low"
                })
        
        return suggestions
    
    async def recalculate_all_weights(self):
        """Recalculate all pattern weights from historical data"""
        logger.info("Recalculating all pattern weights...")
        
        for pattern_id, stats in self.pattern_stats.items():
            adjustment = self._calculate_confidence_adjustment(stats)
            stats.confidence_adjustment = adjustment
            
            # Apply to pattern matcher
            if self.pattern_matcher:
                pattern = self.pattern_matcher.get_pattern_by_id(pattern_id)
                if pattern:
                    pattern.learned_weight_adjustment = adjustment
        
        logger.info(f"Recalculated weights for {len(self.pattern_stats)} patterns")
    
    def export_learning_data(self) -> Dict[str, Any]:
        """Export all learning data for backup/analysis"""
        return {
            "export_timestamp": datetime.utcnow().isoformat(),
            "total_events": len(self.feedback_events),
            "pattern_stats": {
                pid: {
                    "total_matches": s.total_matches,
                    "true_positive_count": s.true_positive_count,
                    "false_positive_count": s.false_positive_count,
                    "accuracy_rate": s.accuracy_rate,
                    "confidence_adjustment": s.confidence_adjustment,
                    "accuracy_by_target": s.accuracy_by_target,
                    "trend": s.trend
                }
                for pid, s in self.pattern_stats.items()
            },
            "scanner_stats": {
                sid: {
                    "total_findings": s.total_findings,
                    "true_positives": s.true_positives,
                    "false_positives": s.false_positives,
                    "overall_accuracy": s.overall_accuracy,
                    "accuracy_by_target": s.accuracy_by_target,
                    "high_severity_ratio": s.high_severity_ratio
                }
                for sid, s in self.scanner_stats.items()
            }
        }
    
    def import_learning_data(self, data: Dict[str, Any]):
        """Import learning data from backup"""
        try:
            for pid, stats_dict in data.get("pattern_stats", {}).items():
                self.pattern_stats[pid] = PatternStats(
                    pattern_id=pid,
                    total_matches=stats_dict.get("total_matches", 0),
                    true_positive_count=stats_dict.get("true_positive_count", 0),
                    false_positive_count=stats_dict.get("false_positive_count", 0),
                    accuracy_rate=stats_dict.get("accuracy_rate", 0.5),
                    confidence_adjustment=stats_dict.get("confidence_adjustment", 0.0),
                    accuracy_by_target=stats_dict.get("accuracy_by_target", {}),
                    trend=stats_dict.get("trend", "stable")
                )
            
            for sid, stats_dict in data.get("scanner_stats", {}).items():
                self.scanner_stats[sid] = ScannerStats(
                    scanner_id=sid,
                    total_findings=stats_dict.get("total_findings", 0),
                    true_positives=stats_dict.get("true_positives", 0),
                    false_positives=stats_dict.get("false_positives", 0),
                    overall_accuracy=stats_dict.get("overall_accuracy", 0.5),
                    accuracy_by_target=stats_dict.get("accuracy_by_target", {}),
                    high_severity_ratio=stats_dict.get("high_severity_ratio", 0.0)
                )
            
            logger.info(
                f"Imported {len(self.pattern_stats)} pattern stats, "
                f"{len(self.scanner_stats)} scanner stats"
            )
        except Exception as e:
            logger.error(f"Failed to import learning data: {e}")


# Convenience function
async def record_user_feedback(
    finding_id: str,
    feedback_type: str,  # "confirmed" or "false_positive"
    pattern_ids: List[str] = None,
    scanner_id: str = "unknown"
) -> Dict[str, Any]:
    """Quick feedback recording without instantiation"""
    learner = FeedbackLearner()
    
    feedback = FeedbackType.CONFIRMED if feedback_type == "confirmed" else FeedbackType.FALSE_POSITIVE
    
    return await learner.record_feedback(
        finding_id=finding_id,
        scan_id="",
        feedback_type=feedback,
        pattern_ids=pattern_ids or [],
        scanner_id=scanner_id,
        vuln_type="unknown",
        original_severity="medium",
        original_confidence=0.5
    )
