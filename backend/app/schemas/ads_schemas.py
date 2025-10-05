from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import uuid

class ADSStageEnum(str, Enum):
    GOAL = "goal"
    CATEGORISATION = "categorisation"
    STRATEGY_ABSTRACT = "strategy_abstract"
    TECHNICAL_CONTEXT = "technical_context"
    BLIND_SPOTS = "blind_spots"
    FALSE_POSITIVES = "false_positives"
    VALIDATION = "validation"
    PRIORITY = "priority"
    RESPONSE = "response"

class PriorityLevelEnum(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# User Schemas
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    is_active: bool
    is_admin: bool
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

# Detection Rule Schemas
class DetectionRuleCreate(BaseModel):
    name: str
    goal: Optional[str] = None

class DetectionRuleUpdate(BaseModel):
    name: Optional[str] = None
    current_stage: Optional[ADSStageEnum] = None
    goal: Optional[str] = None
    mitre_tactics: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    strategy_abstract: Optional[str] = None
    technical_context: Optional[Dict[str, Any]] = None
    blind_spots: Optional[str] = None
    false_positives: Optional[str] = None
    validation_steps: Optional[List[Dict[str, Any]]] = None
    priority_level: Optional[PriorityLevelEnum] = None
    response_procedures: Optional[str] = None

class DetectionRuleResponse(BaseModel):
    id: uuid.UUID
    name: str
    version: str
    current_stage: ADSStageEnum
    is_completed: bool
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime
    goal: Optional[str] = None
    mitre_tactics: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    strategy_abstract: Optional[str] = None
    technical_context: Optional[Dict[str, Any]] = None
    blind_spots: Optional[str] = None
    false_positives: Optional[str] = None
    validation_steps: Optional[List[Dict[str, Any]]] = None
    priority_level: Optional[PriorityLevelEnum] = None
    response_procedures: Optional[str] = None
    sigma_rule: Optional[str] = None
    splunk_query: Optional[str] = None
    elastic_query: Optional[str] = None

    class Config:
        from_attributes = True
