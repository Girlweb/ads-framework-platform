from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
import os
from dotenv import load_dotenv

from .db.database import get_db
from .db import create_tables
from .models.ads_framework import User, DetectionRule
from .schemas.ads_schemas import (
    UserCreate, UserResponse, Token,
    DetectionRuleCreate, DetectionRuleUpdate, DetectionRuleResponse
)
from .core.security import security_manager
from contextlib import asynccontextmanager
load_dotenv()

# Create FastAPI app
app = FastAPI(
    title="ADS Framework Automation Platform",
    description="Detection Engineering Management System following Palantir's ADS Framework",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create database tables on startup
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    create_tables()
    yield
    # Shutdown (if needed)

# Update the FastAPI app creation
app = FastAPI(
    title="ADS Framework Automation Platform",
    description="Detection Engineering Management System following Palantir's ADS Framework",
    version="1.0.0",
    lifespan=lifespan
)
#@app.on_event("startup")
#def startup_event():
 #   create_tables()

# Health check
@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "ADS Framework Platform"}

# Authentication endpoints
@app.post("/auth/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    # Check if user exists
    existing_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    # Create new user
    hashed_password = security_manager.get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user

@app.post("/auth/login", response_model=Token)
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    
    if not user or not security_manager.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")))
    access_token = security_manager.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

# Detection Rules endpoints
@app.post("/detection-rules", response_model=DetectionRuleResponse)
def create_detection_rule(
    rule: DetectionRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(security_manager.get_current_user)
):
    db_rule = DetectionRule(
        name=rule.name,
        goal=rule.goal,
        created_by=current_user.id
    )
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    
    return db_rule

@app.get("/detection-rules", response_model=list[DetectionRuleResponse])
def get_detection_rules(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(security_manager.get_current_user)
):
    rules = db.query(DetectionRule).filter(
        DetectionRule.created_by == current_user.id
    ).offset(skip).limit(limit).all()
    
    return rules

@app.get("/detection-rules/{rule_id}", response_model=DetectionRuleResponse)
def get_detection_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(security_manager.get_current_user)
):
    rule = db.query(DetectionRule).filter(
        DetectionRule.id == rule_id,
        DetectionRule.created_by == current_user.id
    ).first()
    
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    
    return rule

@app.put("/detection-rules/{rule_id}", response_model=DetectionRuleResponse)
def update_detection_rule(
    rule_id: str,
    rule_update: DetectionRuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(security_manager.get_current_user)
):
    rule = db.query(DetectionRule).filter(
        DetectionRule.id == rule_id,
        DetectionRule.created_by == current_user.id
    ).first()
    
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    
    # Update fields
    for field, value in rule_update.dict(exclude_unset=True).items():
        setattr(rule, field, value)
    
    db.commit()
    db.refresh(rule)
    
    return rule

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
