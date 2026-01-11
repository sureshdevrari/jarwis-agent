"""Check user2 scan issues and optionally fix stuck scans"""
import asyncio
import sys
from datetime import datetime, timedelta
from database.connection import AsyncSessionLocal
from database.models import ScanHistory, User
from sqlalchemy import select, update

# Try to import scan_progress - may fail if module structure differs
try:
    from api.routes.scans import scan_progress
    HAS_SCAN_PROGRESS = True
except ImportError:
    scan_progress = {}
    HAS_SCAN_PROGRESS = False

async def check_user2(fix_stuck=False):
    async with AsyncSessionLocal() as db:
        # Get user2
        result = await db.execute(select(User).where(User.email == 'user2@jarwis.ai'))
        user2 = result.scalar_one_or_none()
        
        if not user2:
            print('User2 not found')
            return
            
        print(f'User2 ID: {user2.id}')
        print(f'Plan: {user2.plan}')
        print()
        
        # Get recent scans
        scans_result = await db.execute(
            select(ScanHistory)
            .where(ScanHistory.user_id == user2.id)
            .order_by(ScanHistory.started_at.desc())
            .limit(10)
        )
        scans = scans_result.scalars().all()
        
        print(f'Recent scans ({len(scans)}):')
        stuck_scans = []
        
        for s in scans:
            phase = s.phase or 'N/A'
            is_stuck = False
            stuck_reason = ""
            
            # Check if scan is stuck (running for more than 30 minutes without progress)
            if s.status == 'running' and s.started_at:
                age = datetime.utcnow() - s.started_at
                if age > timedelta(minutes=30):
                    is_stuck = True
                    stuck_reason = f"Running for {age.total_seconds() // 60:.0f} minutes"
                    stuck_scans.append(s)
            
            print(f'  Scan ID: {s.scan_id}')
            print(f'    DB ID: {s.id}')
            print(f'    Type: {s.scan_type}')
            print(f'    Status: {s.status}' + (' ** STUCK **' if is_stuck else ''))
            print(f'    Phase: {phase}')
            print(f'    Progress: {s.progress}%')
            print(f'    Target: {s.target_url}')
            print(f'    Started: {s.started_at}')
            print(f'    Error: {s.error_message or "None"}')
            
            if is_stuck:
                print(f'    >> STUCK REASON: {stuck_reason}')
            
            # Check if scan is in memory progress dict
            if HAS_SCAN_PROGRESS and s.scan_id in scan_progress:
                print(f'    ** In-memory progress: {scan_progress[s.scan_id]}')
            print()
        
        # Fix stuck scans if requested
        if fix_stuck and stuck_scans:
            print(f"\n{'='*50}")
            print(f"FIXING {len(stuck_scans)} STUCK SCANS...")
            print(f"{'='*50}")
            
            for s in stuck_scans:
                print(f"  Marking scan {s.scan_id} as 'error'...")
                s.status = 'error'
                s.error_message = 'Scan timed out - marked as stuck by diagnostic tool'
                s.completed_at = datetime.utcnow()
                
            await db.commit()
            print("  DONE - Stuck scans have been marked as errored")
        elif stuck_scans:
            print(f"\n** Found {len(stuck_scans)} stuck scans. Run with --fix to mark them as errored **")

if __name__ == '__main__':
    fix = '--fix' in sys.argv
    asyncio.run(check_user2(fix_stuck=fix))
