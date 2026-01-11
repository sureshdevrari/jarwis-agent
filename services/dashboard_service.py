"""
Dashboard Service - Unified Security Console Backend
Provides aggregated data for enterprise dashboard including security scoring,
risk heatmaps, and platform breakdowns.
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, desc, select
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from database.models import ScanHistory, Finding, User
from shared.constants import PLAN_LIMITS

logger = logging.getLogger(__name__)


class DashboardService:
    """Service for unified dashboard data aggregation and security scoring"""
    
    # Security score weights per severity
    SEVERITY_WEIGHTS = {
        "critical": 10.0,
        "high": 5.0,
        "medium": 2.0,
        "low": 0.5,
        "info": 0.1
    }
    
    # Base score (perfect security state)
    MAX_SECURITY_SCORE = 100
    
    @staticmethod
    async def calculate_security_score(
        db: AsyncSession,
        user_id: int,
        days: int = 30
    ) -> Dict:
        """
        Calculate overall security score (0-100) based on recent vulnerabilities
        
        Score calculation:
        - Start with 100 (perfect security)
        - Deduct points based on vulnerability severity
        - Apply confidence multiplier for high-confidence findings
        - Consider age of findings (recent = higher impact)
        
        Args:
            db: Async database session
            user_id: User ID
            days: Look-back period (default 30 days)
            
        Returns:
            {
                "score": 85,
                "grade": "B",
                "delta": -5,  # Change from last period
                "breakdown": {
                    "web": 90,
                    "mobile": 85,
                    "cloud": 80,
                    "network": 75
                },
                "total_vulnerabilities": 42,
                "critical_count": 2,
                "trend": "declining"  # improving, stable, declining
            }
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            previous_cutoff = cutoff_date - timedelta(days=days)
            
            # Get current period vulnerabilities using async query
            current_stmt = select(Finding).join(ScanHistory).where(
                and_(
                    ScanHistory.user_id == user_id,
                    ScanHistory.started_at >= cutoff_date,
                    ScanHistory.status == 'completed'
                )
            )
            current_result = await db.execute(current_stmt)
            current_vulns = current_result.scalars().all()
            
            # Get previous period for delta calculation
            previous_stmt = select(Finding).join(ScanHistory).where(
                and_(
                    ScanHistory.user_id == user_id,
                    ScanHistory.started_at >= previous_cutoff,
                    ScanHistory.started_at < cutoff_date,
                    ScanHistory.status == 'completed'
                )
            )
            previous_result = await db.execute(previous_stmt)
            previous_vulns = previous_result.scalars().all()
            
            # Calculate current score
            current_deduction = DashboardService._calculate_deduction(current_vulns)
            current_score = max(0, DashboardService.MAX_SECURITY_SCORE - current_deduction)
            
            # Calculate previous score for delta
            previous_deduction = DashboardService._calculate_deduction(previous_vulns)
            previous_score = max(0, DashboardService.MAX_SECURITY_SCORE - previous_deduction)
            
            delta = round(current_score - previous_score, 1)
            
            # Determine trend
            if delta > 2:
                trend = "improving"
            elif delta < -2:
                trend = "declining"
            else:
                trend = "stable"
            
            # Calculate grade
            grade = DashboardService._score_to_grade(current_score)
            
            # Calculate per-platform breakdown
            breakdown = await DashboardService._calculate_platform_scores(db, user_id, cutoff_date)
            
            # Count severities
            severity_counts = {
                "critical": len([v for v in current_vulns if v.severity == "critical"]),
                "high": len([v for v in current_vulns if v.severity == "high"]),
                "medium": len([v for v in current_vulns if v.severity == "medium"]),
                "low": len([v for v in current_vulns if v.severity == "low"]),
                "info": len([v for v in current_vulns if v.severity == "info"])
            }
            
            return {
                "score": round(current_score, 1),
                "grade": grade,
                "delta": delta,
                "breakdown": breakdown,
                "total_vulnerabilities": len(current_vulns),
                "critical_count": severity_counts["critical"],
                "high_count": severity_counts["high"],
                "medium_count": severity_counts["medium"],
                "low_count": severity_counts["low"],
                "info_count": severity_counts["info"],
                "trend": trend,
                "period_days": days,
                "last_updated": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error calculating security score: {str(e)}")
            # Return safe defaults on error
            return {
                "score": 0,
                "grade": "F",
                "delta": 0,
                "breakdown": {"web": 0, "mobile": 0, "cloud": 0, "network": 0},
                "total_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
                "trend": "unknown",
                "period_days": days,
                "last_updated": datetime.utcnow().isoformat()
            }
    
    @staticmethod
    def _calculate_deduction(vulnerabilities: List[Finding]) -> float:
        """Calculate total score deduction from vulnerability list"""
        total_deduction = 0.0
        
        for vuln in vulnerabilities:
            severity = vuln.severity.lower() if hasattr(vuln, 'severity') and vuln.severity else "info"
            base_weight = DashboardService.SEVERITY_WEIGHTS.get(severity, 0.1)
            
            # Apply confidence multiplier (if available)
            confidence = getattr(vuln, 'confidence_score', 0.8)
            confidence_multiplier = confidence if confidence > 0 else 0.8
            
            # Apply age decay (older findings have less impact) - use scan start time
            created = getattr(vuln, 'created_at', datetime.utcnow())
            age_days = (datetime.utcnow() - created).days
            age_multiplier = max(0.5, 1.0 - (age_days / 90))  # Decay over 90 days
            
            deduction = base_weight * confidence_multiplier * age_multiplier
            total_deduction += deduction
        
        return total_deduction
    
    @staticmethod
    def _score_to_grade(score: float) -> str:
        """Convert numeric score to letter grade"""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    @staticmethod
    @staticmethod
    async def _calculate_platform_scores(
        db: AsyncSession,
        user_id: int,
        cutoff_date: datetime
    ) -> Dict[str, float]:
        """Calculate security scores per platform"""
        scores = {}
        
        # Web scans
        web_stmt = select(Finding).join(ScanHistory).where(
            and_(
                ScanHistory.user_id == user_id,
                ScanHistory.scan_type == 'web',
                ScanHistory.started_at >= cutoff_date,
                ScanHistory.status == 'completed'
            )
        )
        web_result = await db.execute(web_stmt)
        web_vulns = web_result.scalars().all()
        web_deduction = DashboardService._calculate_deduction(web_vulns)
        scores["web"] = round(max(0, DashboardService.MAX_SECURITY_SCORE - web_deduction), 1)
        
        # Mobile scans
        mobile_stmt = select(Finding).join(ScanHistory).where(
            and_(
                ScanHistory.user_id == user_id,
                ScanHistory.scan_type == 'mobile',
                ScanHistory.started_at >= cutoff_date,
                ScanHistory.status == 'completed'
            )
        )
        mobile_result = await db.execute(mobile_stmt)
        mobile_vulns = mobile_result.scalars().all()
        mobile_deduction = DashboardService._calculate_deduction(mobile_vulns)
        scores["mobile"] = round(max(0, DashboardService.MAX_SECURITY_SCORE - mobile_deduction), 1)
        
        # Cloud scans
        cloud_stmt = select(Finding).join(ScanHistory).where(
            and_(
                ScanHistory.user_id == user_id,
                ScanHistory.scan_type == 'cloud',
                ScanHistory.started_at >= cutoff_date,
                ScanHistory.status == 'completed'
            )
        )
        cloud_result = await db.execute(cloud_stmt)
        cloud_vulns = cloud_result.scalars().all()
        cloud_deduction = DashboardService._calculate_deduction(cloud_vulns)
        scores["cloud"] = round(max(0, DashboardService.MAX_SECURITY_SCORE - cloud_deduction), 1)
        
        # Network scans
        network_stmt = select(Finding).join(ScanHistory).where(
            and_(
                ScanHistory.user_id == user_id,
                ScanHistory.scan_type == 'network',
                ScanHistory.started_at >= cutoff_date,
                ScanHistory.status == 'completed'
            )
        )
        network_result = await db.execute(network_stmt)
        network_vulns = network_result.scalars().all()
        network_deduction = DashboardService._calculate_deduction(network_vulns)
        scores["network"] = round(max(0, DashboardService.MAX_SECURITY_SCORE - network_deduction), 1)
        
        return scores
    
    @staticmethod
    async def get_risk_heatmap(
        db: AsyncSession,
        user_id: int,
        days: int = 30
    ) -> Dict:
        """
        Generate risk heatmap matrix: Platform × Severity
        
        Returns:
            {
                "matrix": [
                    {"platform": "web", "critical": 2, "high": 5, "medium": 10, "low": 8, "total": 25},
                    {"platform": "mobile", "critical": 0, "high": 3, "medium": 7, "low": 5, "total": 15},
                    {"platform": "cloud", "critical": 1, "high": 4, "medium": 6, "low": 3, "total": 14},
                    {"platform": "network", "critical": 3, "high": 2, "medium": 5, "low": 4, "total": 14}
                ],
                "totals": {
                    "critical": 6,
                    "high": 14,
                    "medium": 28,
                    "low": 20,
                    "total": 68
                }
            }
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Query vulnerabilities grouped by platform and severity
            stmt = select(
                ScanHistory.scan_type,
                Finding.severity,
                func.count(Finding.id).label('count')
            ).join(ScanHistory).where(
                and_(
                    ScanHistory.user_id == user_id,
                    ScanHistory.started_at >= cutoff_date,
                    ScanHistory.status == 'completed'
                )
            ).group_by(ScanHistory.scan_type, Finding.severity)
            
            result = await db.execute(stmt)
            results = result.all()
            
            # Build matrix
            platforms = ["web", "mobile", "cloud", "network"]
            severities = ["critical", "high", "medium", "low", "info"]
            
            matrix = []
            totals = {s: 0 for s in severities}
            totals["total"] = 0
            
            for platform in platforms:
                row = {"platform": platform}
                row_total = 0
                
                for severity in severities:
                    # Find count for this platform/severity combination
                    count = 0
                    for row_result in results:
                        scan_type_str = str(row_result.scan_type).lower() if row_result.scan_type else "unknown"
                        result_severity = str(row_result.severity).lower() if row_result.severity else "info"
                        
                        if scan_type_str == platform and result_severity == severity:
                            count = row_result.count
                            break
                    
                    row[severity] = count
                    totals[severity] += count
                    row_total += count
                
                row["total"] = row_total
                totals["total"] += row_total
                matrix.append(row)
            
            return {
                "matrix": matrix,
                "totals": totals,
                "period_days": days,
                "last_updated": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating risk heatmap: {str(e)}")
            return {
                "matrix": [],
                "totals": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                "period_days": days,
                "last_updated": datetime.utcnow().isoformat()
            }
    
    @staticmethod
    async def get_platform_breakdown(
        db: AsyncSession,
        user_id: int,
        days: int = 30
    ) -> Dict:
        """
        Get platform risk breakdown for horizontal bar chart
        
        Returns:
            {
                "platforms": [
                    {
                        "name": "web",
                        "risk_score": 65,  # 0-100, higher = more risk
                        "vulnerability_count": 25,
                        "critical_count": 2,
                        "scan_count": 10,
                        "last_scan": "2026-01-07T10:30:00Z"
                    },
                    ...
                ]
            }
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            platforms = ["web", "mobile", "cloud", "network"]
            platform_data = []
            
            for platform in platforms:
                # Get scans for this platform
                scans_stmt = select(ScanHistory).where(
                    and_(
                        ScanHistory.user_id == user_id,
                        ScanHistory.scan_type == platform,
                        ScanHistory.started_at >= cutoff_date
                    )
                )
                scans_result = await db.execute(scans_stmt)
                scans = scans_result.scalars().all()
                
                if not scans:
                    platform_data.append({
                        "name": platform,
                        "risk_score": 0,
                        "vulnerability_count": 0,
                        "critical_count": 0,
                        "scan_count": 0,
                        "last_scan": None
                    })
                    continue
                
                # Get vulnerabilities for this platform
                vulns_stmt = select(Finding).join(ScanHistory).where(
                    and_(
                        ScanHistory.user_id == user_id,
                        ScanHistory.scan_type == platform,
                        ScanHistory.started_at >= cutoff_date,
                        ScanHistory.status == 'completed'
                    )
                )
                vulns_result = await db.execute(vulns_stmt)
                vulns = vulns_result.scalars().all()
                
                # Calculate risk score (inverse of security score)
                deduction = DashboardService._calculate_deduction(vulns)
                security_score = max(0, DashboardService.MAX_SECURITY_SCORE - deduction)
                risk_score = round(100 - security_score, 1)
                
                # Count critical vulnerabilities
                critical_count = len([v for v in vulns if v.severity == "critical"])
                
                # Get last scan date
                last_scan = max([s.started_at for s in scans]) if scans else None
                
                platform_data.append({
                    "name": platform,
                    "risk_score": risk_score,
                    "vulnerability_count": len(vulns),
                    "critical_count": critical_count,
                    "scan_count": len(scans),
                    "last_scan": last_scan.isoformat() if last_scan else None
                })
            
            return {
                "platforms": platform_data,
                "period_days": days,
                "last_updated": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating platform breakdown: {str(e)}")
            return {
                "platforms": [],
                "period_days": days,
                "last_updated": datetime.utcnow().isoformat()
            }
    
    @staticmethod
    async def get_scan_stats(
        db: AsyncSession,
        user_id: int,
        days: int = 30
    ) -> Dict:
        """
        Get aggregated scan statistics across all platforms
        
        Returns:
            {
                "total_scans": 45,
                "completed_scans": 40,
                "running_scans": 2,
                "failed_scans": 3,
                "scans_by_type": {
                    "web": 20,
                    "mobile": 10,
                    "cloud": 8,
                    "network": 7
                },
                "avg_scan_duration_seconds": 120,
                "total_vulnerabilities": 156
            }
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Get all scans for user in period
            scans_stmt = select(ScanHistory).where(
                and_(
                    ScanHistory.user_id == user_id,
                    ScanHistory.started_at >= cutoff_date
                )
            )
            scans_result = await db.execute(scans_stmt)
            scans = scans_result.scalars().all()
            
            # Count by status
            completed = len([s for s in scans if s.status == 'completed'])
            running = len([s for s in scans if s.status == 'running'])
            failed = len([s for s in scans if s.status in ['error', 'failed']])
            
            # Count by type
            scans_by_type = {
                "web": len([s for s in scans if s.scan_type == 'web']),
                "mobile": len([s for s in scans if s.scan_type == 'mobile']),
                "cloud": len([s for s in scans if s.scan_type == 'cloud']),
                "network": len([s for s in scans if s.scan_type == 'network'])
            }
            
            # Calculate average duration for completed scans
            completed_with_duration = [
                s for s in scans 
                if s.status == 'completed' and s.completed_at and s.started_at
            ]
            if completed_with_duration:
                avg_duration = sum([
                    (s.completed_at - s.started_at).total_seconds() 
                    for s in completed_with_duration
                ]) / len(completed_with_duration)
            else:
                avg_duration = 0
            
            # Get total vulnerabilities
            count_stmt = select(func.count(Finding.id)).join(ScanHistory).where(
                and_(
                    ScanHistory.user_id == user_id,
                    ScanHistory.started_at >= cutoff_date
                )
            )
            count_result = await db.execute(count_stmt)
            total_vulns = count_result.scalar() or 0
            
            return {
                "total_scans": len(scans),
                "completed_scans": completed,
                "running_scans": running,
                "failed_scans": failed,
                "scans_by_type": scans_by_type,
                "avg_scan_duration_seconds": round(avg_duration, 1),
                "total_vulnerabilities": total_vulns,
                "period_days": days,
                "last_updated": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting scan stats: {str(e)}")
            return {
                "total_scans": 0,
                "completed_scans": 0,
                "running_scans": 0,
                "failed_scans": 0,
                "scans_by_type": {"web": 0, "mobile": 0, "cloud": 0, "network": 0},
                "avg_scan_duration_seconds": 0,
                "total_vulnerabilities": 0,
                "period_days": days,
                "last_updated": datetime.utcnow().isoformat()
            }
    @staticmethod
    async def get_recent_scans(
        db: AsyncSession,
        user_id: int,
        limit: int = 10
    ) -> List[Dict]:
        """
        Get recent scans for the dashboard table
        
        Returns list of recent scan objects with:
        - id, date, type, target, status, findings count, max severity
        """
        try:
            stmt = select(ScanHistory).where(
                ScanHistory.user_id == user_id
            ).order_by(desc(ScanHistory.started_at)).limit(limit)
            
            result = await db.execute(stmt)
            scans = result.scalars().all()
            
            recent = []
            for scan in scans:
                # Get findings count for this scan
                findings_stmt = select(func.count(Finding.id)).where(
                    Finding.scan_id == scan.id
                )
                findings_result = await db.execute(findings_stmt)
                findings_count = findings_result.scalar() or 0
                
                # Get max severity
                severity_stmt = select(Finding.severity).where(
                    Finding.scan_id == scan.id
                )
                severity_result = await db.execute(severity_stmt)
                severities = [r for r in severity_result.scalars().all()]
                
                severity_order = ["critical", "high", "medium", "low", "info"]
                max_severity = "none"
                for sev in severity_order:
                    if sev in severities:
                        max_severity = sev
                        break
                
                recent.append({
                    "id": str(scan.id),
                    "date": scan.started_at.strftime("%Y-%m-%d") if scan.started_at else "",
                    "type": (scan.scan_type or "web").capitalize(),
                    "target": scan.target_url or "",
                    "status": (scan.status or "pending").capitalize(),
                    "findings": findings_count,
                    "severity": max_severity
                })
            
            return recent
            
        except Exception as e:
            logger.error(f"Error getting recent scans: {str(e)}")
            return []

    @staticmethod
    async def get_top_vulnerabilities(
        db: AsyncSession,
        user_id: int,
        limit: int = 10
    ) -> List[Dict]:
        """
        Get top vulnerabilities sorted by severity for the dashboard
        
        Returns list of vulnerability objects with:
        - id, title, severity, affected component, status, date
        """
        try:
            # Get findings from user's scans
            stmt = select(Finding).join(ScanHistory).where(
                ScanHistory.user_id == user_id
            ).order_by(desc(Finding.created_at)).limit(limit * 3)  # Get more to filter
            
            result = await db.execute(stmt)
            findings = result.scalars().all()
            
            # Sort by severity manually
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(
                findings,
                key=lambda f: (severity_order.get(f.severity.lower() if f.severity else "info", 5), f.created_at),
            )[:limit]
            
            vulns = []
            for finding in sorted_findings:
                vulns.append({
                    "id": str(finding.id),
                    "title": finding.title or finding.finding_type or "Unknown",
                    "severity": (finding.severity or "info").lower(),
                    "affected": finding.affected_component or finding.affected_url or "N/A",
                    "status": "Open",  # Default status
                    "date": finding.created_at.strftime("%Y-%m-%d") if finding.created_at else ""
                })
            
            return vulns
            
        except Exception as e:
            logger.error(f"Error getting top vulnerabilities: {str(e)}")
            return []