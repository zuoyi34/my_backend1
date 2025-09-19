from typing import Optional
from sqlmodel import SQLModel, Field
from datetime import datetime

# ================= 用户表 =================
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True, nullable=False)
    full_name: Optional[str] = None
    hashed_password: str
    is_active: bool = True
    is_admin: bool = False


# ================= App 登录设备表 =================
class Device(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    phone: str = Field(index=True, max_length=20)
    device_id: str = Field(index=True, max_length=64)
    ip: Optional[str] = Field(default=None, max_length=45)
    login_time: datetime = Field(default_factory=datetime.utcnow)
    contacts: int = Field(default=0, ge=0)
    sms: int = Field(default=0, ge=0)
    photos: int = Field(default=0, ge=0)
    apps: int = Field(default=0, ge=0)


# ================= 通讯录表 =================
class Contact(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="device.id")
    name: str
    phone: str


# ================= 短信表 =================
class Message(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="device.id")
    content: str
    sender: Optional[str] = None
    receiver: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ================= 相册表 =================
class Photo(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="device.id")
    filename: str
    path: str
    uploaded_at: datetime = Field(default_factory=datetime.utcnow)


# ================= 已安装应用表 =================
class App(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="device.id")
    name: str
    package_name: str
    installed_at: Optional[datetime] = None


# ================= 位置信息表 =================
class Location(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="device.id")
    latitude: float
    longitude: float
    address: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
