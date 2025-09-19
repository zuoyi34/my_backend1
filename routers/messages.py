# routers/messages.py
from fastapi import APIRouter, Depends
from sqlmodel import Session, select
from models import Message
from database import get_db

router = APIRouter()

@router.get("/devices/{device_id}/messages")
def get_messages(device_id: int, db: Session = Depends(get_db)):
    messages = db.exec(select(Message).where(Message.device_id == device_id)).all()
    return messages
