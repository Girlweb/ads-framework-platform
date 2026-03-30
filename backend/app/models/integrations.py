from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
from .ads_framework import Base

class Integration(Base):
    __tablename__ = "integrations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    integration_type = Column(String(50))  # SIEM, EDR, TIP, Firewall
    connector_class = Column(String(100))  # Python class name
    config = Column(JSONB)  # Encrypted configuration
    is_active = Column(Boolean, default=True)
    last_sync = Column(DateTime)
    created_at = Column(DateTime, server_default=func.now())
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Relationships
    alerts = relationship("Alert", back_populates="source_integration")

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_integration_id = Column(UUID(as_uuid=True), ForeignKey("integrations.id"))
    external_id = Column(String(255))  # ID in source system
    severity = Column(String(20))  # low, medium, high, critical
    title = Column(String(500))
    description = Column(Text)
    raw_data = Column(JSONB)  # Original alert data
    normalized_data = Column(JSONB)  # Standardized format
    status = Column(String(50), default='new')  # new, investigating, resolved
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    # Enrichment data
    enrichment_data = Column(JSONB)
    threat_score = Column(Integer)  # 0-100
    mitre_tactics = Column(JSONB)
    mitre_techniques = Column(JSONB)
    
    # Relationships
    source_integration = relationship("Integration", back_populates="alerts")

class Playbook(Base):
    __tablename__ = "playbooks"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    trigger_conditions = Column(JSONB)
    steps = Column(JSONB)  # Ordered list of actions
    is_active = Column(Boolean, default=True)
    requires_approval = Column(Boolean, default=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(DateTime, server_default=func.now())
    
    # Metrics
    execution_count = Column(Integer, default=0)
    success_rate = Column(Integer)
    avg_execution_time = Column(Integer)

class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    playbook_id = Column(UUID(as_uuid=True), ForeignKey("playbooks.id"))
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"))
    status = Column(String(50))  # running, completed, failed
    started_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime)
    execution_log = Column(JSONB)
    error_message = Column(Text)
