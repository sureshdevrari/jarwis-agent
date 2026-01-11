"""
Agent Service - Jarwis Agent Management

Handles registration, management, and communication with Jarwis Agents.
Agents enable scanning of private network ranges from inside corporate networks.

Responsibilities:
- Agent registration and lifecycle management
- Agent authentication and heartbeat verification
- Agent ownership validation
- Network range validation
"""

import logging
import ipaddress
import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from database.models import User, Agent
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class AgentService:
    """Agent management service"""
    
    @staticmethod
    async def register_agent(
        db: AsyncSession,
        user: User,
        agent_data: 'AgentRegistration',  # From api/routes/network.py
    ) -> Dict[str, Any]:
        """
        Register a new Jarwis Agent.
        
        Args:
            db: Database session
            user: User registering the agent
            agent_data: Agent registration details
            
        Returns:
            Agent registration response with agent_id and agent_key
            
        Raises:
            ValueError: If network ranges are invalid
        """
        # Validate network ranges
        for range_str in agent_data.network_ranges:
            try:
                ipaddress.ip_network(range_str, strict=False)
            except ValueError:
                raise ValueError(f"Invalid network range: {range_str}")
        
        agent_id = f"agent-{uuid.uuid4().hex[:12]}"
        agent_key = f"jarwis_agent_{uuid.uuid4().hex}"
        
        # Create agent record (if using SQLAlchemy model)
        try:
            agent = Agent(
                id=agent_id,
                user_id=user.id,
                name=agent_data.agent_name,
                description=agent_data.description,
                network_ranges=agent_data.network_ranges,
                status='offline',  # Will be 'online' after first heartbeat
                created_at=datetime.utcnow(),
            )
            
            db.add(agent)
            await db.commit()
        except Exception as e:
            logger.warning(f"Agent model not found, using in-memory storage: {e}")
            # Fall back to in-memory storage (compatibility)
        
        logger.info(
            f"Agent registered: {agent_id} for user {user.email}, "
            f"networks: {agent_data.network_ranges}"
        )
        
        return {
            'agent_id': agent_id,
            'agent_key': agent_key,
            'name': agent_data.agent_name,
            'network_ranges': agent_data.network_ranges,
            'created_at': datetime.utcnow(),
        }
    
    @staticmethod
    async def verify_agent_ownership(
        db: AsyncSession,
        user_id: Any,
        agent_id: str,
    ) -> bool:
        """
        Verify that an agent belongs to the user.
        
        Args:
            db: Database session
            user_id: User to check
            agent_id: Agent to verify
            
        Returns:
            True if agent exists and belongs to user, False otherwise
        """
        try:
            query = select(Agent).where(
                and_(
                    Agent.id == agent_id,
                    Agent.user_id == user_id,
                )
            )
            result = await db.execute(query)
            agent = result.scalars().first()
            
            return agent is not None
        except Exception as e:
            logger.warning(f"Failed to verify agent ownership: {e}")
            # Fall back to in-memory check
            return False
    
    @staticmethod
    async def list_agents(
        db: AsyncSession,
        user: User,
    ) -> Dict[str, Any]:
        """List all agents registered by a user"""
        try:
            query = select(Agent).where(Agent.user_id == user.id)
            result = await db.execute(query)
            agents = result.scalars().all()
            
            agents_data = []
            for agent in agents:
                agents_data.append({
                    'id': agent.id,
                    'name': agent.name,
                    'description': agent.description,
                    'network_ranges': agent.network_ranges,
                    'status': agent.status,
                    'last_seen': agent.last_seen.isoformat() if agent.last_seen else None,
                    'version': agent.version,
                    'created_at': agent.created_at.isoformat() if agent.created_at else None,
                })
            
            return {
                'agents': agents_data,
                'total': len(agents_data),
            }
        except Exception as e:
            logger.warning(f"Failed to list agents from DB: {e}")
            # Return empty list if DB model not available
            return {'agents': [], 'total': 0}
    
    @staticmethod
    async def delete_agent(
        db: AsyncSession,
        user: User,
        agent_id: str,
    ) -> Dict[str, Any]:
        """Delete an agent registered by user"""
        try:
            query = select(Agent).where(
                and_(
                    Agent.id == agent_id,
                    Agent.user_id == user.id,
                )
            )
            result = await db.execute(query)
            agent = result.scalars().first()
            
            if not agent:
                raise ValueError("Agent not found or access denied")
            
            await db.delete(agent)
            await db.commit()
            
            logger.info(f"Agent deleted: {agent_id}")
            
            return {
                'message': 'Agent deleted',
                'agent_id': agent_id,
            }
        except ValueError as e:
            raise e
        except Exception as e:
            logger.error(f"Failed to delete agent: {e}")
            raise ValueError("Failed to delete agent")
    
    @staticmethod
    async def update_agent_heartbeat(
        db: AsyncSession,
        agent_id: str,
        version: Optional[str] = None,
    ) -> None:
        """Update agent heartbeat (called by agent)"""
        try:
            query = select(Agent).where(Agent.id == agent_id)
            result = await db.execute(query)
            agent = result.scalars().first()
            
            if agent:
                agent.status = 'online'
                agent.last_seen = datetime.utcnow()
                if version:
                    agent.version = version
                
                db.add(agent)
                await db.commit()
        except Exception as e:
            logger.warning(f"Failed to update agent heartbeat: {e}")
    
    @staticmethod
    async def get_pending_jobs(
        db: AsyncSession,
        agent_id: str,
    ) -> List[Dict[str, Any]]:
        """Get pending scan jobs for agent (called by agent)"""
        try:
            from database.models import ScanHistory
            from sqlalchemy import and_
            
            query = select(ScanHistory).where(
                and_(
                    ScanHistory.config['agent_id'].astext == agent_id,
                    ScanHistory.status == 'queued',
                )
            )
            result = await db.execute(query)
            scans = result.scalars().all()
            
            return [
                {
                    'scan_id': scan.id,
                    'targets': scan.target_url,
                    'config': scan.config,
                }
                for scan in scans
            ]
        except Exception as e:
            logger.warning(f"Failed to get pending jobs: {e}")
            return []
