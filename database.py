from sqlmodel import SQLModel, create_engine, Session

# 导入所有模型
from models import User, Device, Location, Contact, Message, Photo, App

engine = create_engine("sqlite:///./test.db", echo=True)

def get_session():
    with Session(engine) as session:
        yield session

def get_session_context():
    return Session(engine)

def init_db():
    SQLModel.metadata.create_all(engine)
