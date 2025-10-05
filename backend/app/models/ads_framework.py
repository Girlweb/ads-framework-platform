from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.sql import func
import uuid
import enum
from datetime import datetime

Base = declarative_base()

class ADSStage(enum.Enum):
    GOAL = "goal"
    CATEGORISATION = "categorisation"
    STRATEGY_ABSTRACT = "strategy_abstract"
    TECHNICAL_CONTEXT = "technical_context"
    BLIND_SPOTS = "blind_spots"
    FALSE_POSITIVES = "false_positives"
    VALIDATION = "validation"
    PRIORITY = "priority"
    RESPONSE = "response"

class PriorityLevel(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())
    
    # Relationships
    detection_rules = relationship("DetectionRule", back_populates="created_by_user")

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    version = Column(String(50), nullable=False, default="1.0.0")
    current_stage = Column(Enum(ADSStage), default=ADSStage.GOAL)
    is_completed = Column(Boolean, default=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    # ADS Framework Fields
    goal = Column(Text)
    mitre_tactics = Column(JSONB)  # Array of MITRE ATT&CK tactics
    mitre_techniques = Column(JSONB)  # Array of MITRE ATT&CK techniques
    strategy_abstract = Column(Text)
    technical_context = Column(JSONB)
    blind_spots = Column(Text)
    false_positives = Column(Text)
    validation_steps = Column(JSONB)
    priority_level = Column(Enum(PriorityLevel))
    response_procedures = Column(Text)
    
    # Generated outputs
    sigma_rule = Column(Text)  # Generated Sigma rule
    splunk_query = Column(Text)  # Generated Splunk query
    elastic_query = Column(Text)  # Generated Elastic query
    
    # Relationships
    created_by_user = relationship("User", back_populates="detection_rules")
    validation_tests = relationship("ValidationTest", back_populates="detection_rule")

class ValidationTest(Base):
    __tablename__ = "validation_tests"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    detection_rule_id = Column(UUID(as_uuid=True), ForeignKey("detection_rules.id"))
    test_name = Column(String(255), nullable=False)
    test_description = Column(Text)
    test_script = Column(Text)
    expected_result = Column(Text)
    actual_result = Column(Text)
    test_passed = Column(Boolean)
    executed_at = Column(DateTime)
    
    # Relationships
    detection_rule = relationship("DetectionRule", back_populates="validation_tests")
