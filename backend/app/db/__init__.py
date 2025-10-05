from .database import engine, SessionLocal, get_db
from ..models.ads_framework import Base

def create_tables():
    Base.metadata.create_all(bind=engine)
