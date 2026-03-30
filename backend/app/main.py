from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
import os
from dotenv import load_dotenv
from contextlib import asynccontextmanager

from app.db.database import get_db
from app.db import create_tables
from app.models.ads_framework import User, DetectionRule
from app.schemas.ads_schemas import (
    UserCreate, UserResponse, Token,
    DetectionRuleCreate, DetectionRuleUpdate, DetectionRuleResponse
)
from app.core.security import (
    verify_password, get_password_hash, create_access_token, get_current_user
)
from app.api.integrations import router as integrations_router

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield

app = FastAPI(
    title="ADS Framework Automation Platform",
    description="Detection Engineering Management System following Palantir's ADS Framework",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(integrations_router)

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "ADS Framework Platform"}

@app.post("/auth/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username or email already registered")
    db_user = User(username=user.username, email=user.email, hashed_password=get_password_hash(user.password))
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/auth/login", response_model=Token)
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))))
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/detection-rules", response_model=DetectionRuleResponse)
def create_detection_rule(rule: DetectionRuleCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_rule = DetectionRule(name=rule.name, goal=rule.goal, created_by=current_user.id)
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule

@app.get("/detection-rules", response_model=list[DetectionRuleResponse])
def get_detection_rules(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(DetectionRule).filter(DetectionRule.created_by == current_user.id).offset(skip).limit(limit).all()

@app.get("/detection-rules/{rule_id}", response_model=DetectionRuleResponse)
def get_detection_rule(rule_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id, DetectionRule.created_by == current_user.id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    return rule

@app.put("/detection-rules/{rule_id}", response_model=DetectionRuleResponse)
def update_detection_rule(rule_id: str, rule_update: DetectionRuleUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id, DetectionRule.created_by == current_user.id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    for field, value in rule_update.dict(exclude_unset=True).items():
        setattr(rule, field, value)
    db.commit()
    db.refresh(rule)
    return rule
