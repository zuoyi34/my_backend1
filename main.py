from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
from sqlmodel import Session, select
from passlib.context import CryptContext

from database import get_session
from models import User, Device, Location   # ✅ 加 Device
from auth import verify_password

app = FastAPI()

@app.get("/")
def root():
    return {"status": "ok"}

# 允许跨域（前端才能访问）
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
        'https://vue-admin-custom-production.up.railway.app',
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT 配置
SECRET_KEY = "your-secret-key"   # ⚠️生产环境请换成更复杂的 key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# OAuth2 获取 token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# 密码加密
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 模拟数据库（保留原样，不动）
fake_users_db = {
    "admin": {"username": "admin", "password": "123456", "role": "admin"},
    "user": {"username": "user", "password": "123456", "role": "user"},
}

fake_customers_db = [
    {"id": 1, "name": "张三", "email": "zhangsan@test.com"},
    {"id": 2, "name": "李四", "email": "lisi@test.com"},
]

# 请求体模型
class LoginRequest(BaseModel):
    username: str
    password: str

class AddUserRequest(BaseModel):
    username: str
    password: str

# 生成 Token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# 解码 Token
def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Token 无效或已过期")

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    # 用 email 查询数据库
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="用户名或密码错误")

    role = "admin" if user.is_admin else "user"

    access_token = create_access_token(
        data={"sub": str(user.id), "role": role},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": role,
        "username": user.email,
    }


# 获取客户信息
@app.get("/customers")
def get_customers():
    return fake_customers_db

# 删除客户
@app.delete("/customers/{customer_id}")
def delete_customer(customer_id: int):
    global fake_customers_db
    fake_customers_db = [c for c in fake_customers_db if c["id"] != customer_id]
    return {"message": f"客户 {customer_id} 已删除"}

# 添加用户（仅管理员）
@app.post("/users/add")
def add_user(req: AddUserRequest, token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    payload = decode_token(token)
    if payload["role"] != "admin":
        raise HTTPException(status_code=403, detail="只有管理员可以添加用户")

    # 查重
    existing = session.exec(select(User).where(User.email == req.username)).first()
    if existing:
        raise HTTPException(status_code=400, detail="用户已存在")

    new_user = User(
        email=req.username,
        hashed_password=pwd_context.hash(req.password),  # ✅ 改为哈希存储
        is_admin=False,                # 默认添加普通用户
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    return {"message": f"用户 {req.username} 添加成功"}


from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session, select
from jose import jwt, JWTError

SECRET_KEY = "your-secret-key"   # ⚠️ 确保和 login 生成 token 的一致
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="无效的Token")

@app.get("/users")
def get_users(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session)
):
    payload = decode_token(token)

    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="只有管理员可以查看用户列表")

    users = session.exec(select(User)).all()
    return [
        {
            "email": u.email,
            "role": "admin" if u.is_admin else "user"
        }
        for u in users
    ]


# 删除用户（仅管理员）
@app.delete("/users/{username}")
def delete_user(username: str, token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    payload = decode_token(token)
    if payload["role"] != "admin":
        raise HTTPException(status_code=403, detail="只有管理员可以删除用户")

    user = session.exec(select(User).where(User.email == username)).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    if user.is_admin:
        raise HTTPException(status_code=403, detail="不能删除管理员账号")

    session.delete(user)
    session.commit()

    return {"message": f"用户 {username} 已删除"}


# ===============================
# 📱 手机 App 登录信息相关接口
# ===============================

# App 登录时调用（保存设备信息）
@app.post("/app_login")
def app_login(device: Device, session: Session = Depends(get_session)):
    session.add(device)
    session.commit()
    session.refresh(device)
    return {"message": "登录信息已保存", "id": device.id}


# 后台获取设备登录记录（仅管理员）
@app.get("/devices")
def get_devices(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    payload = decode_token(token)
    if payload["role"] != "admin":
        raise HTTPException(status_code=403, detail="只有管理员可以查看设备列表")

    devices = session.exec(select(Device)).all()
    return devices


# 普通用户通过 ID 搜索设备
@app.get("/device/{device_id}")
def get_device_by_id(
    device_id: int,
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session)
):
    payload = decode_token(token)

    # 管理员 → 不限制，直接查
    if payload["role"] == "admin":
        device = session.get(Device, device_id)
        if not device:
            raise HTTPException(status_code=404, detail="设备不存在")
        return device

    # 普通用户 → 不能查看列表，只能按 ID 查
    device = session.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="设备不存在")

    return device

from fastapi import Path
from sqlmodel import Session
from fastapi import Depends, HTTPException

# 通用函数：根据 ID 获取设备对象（不存在则抛 404）
def get_device_or_404(device_id: int, session: Session) -> Device:
    device = session.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="设备不存在")
    return device

# 获取通讯录数量
@app.get("/devices/{device_id}/contacts")
def get_contacts(
    device_id: int = Path(...),
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session)
):
    decode_token(token)
    device = get_device_or_404(device_id, session)
    return {"device_id": device.id, "contacts": device.contacts}


# 获取短信数量
@app.get("/devices/{device_id}/messages")
def get_messages(
    device_id: int,
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session)
):
    decode_token(token)
    device = get_device_or_404(device_id, session)
    return {
        "device_id": device.id,
        "messages": device.sms  # ✅ 正确取字段名
    }


# 获取相册数量
@app.get("/devices/{device_id}/photos")
def get_photos(
    device_id: int,
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session)
):
    decode_token(token)
    device = get_device_or_404(device_id, session)
    return {"device_id": device.id, "photos": device.photos}


# 获取定位信息
@app.get("/devices/{device_id}/location")
def get_location(
    device_id: int,
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session)
):
    decode_token(token)
    # 确认设备存在
    _ = get_device_or_404(device_id, session)

    # 查询该设备最新的定位信息
    location = session.exec(
        select(Location)
        .where(Location.device_id == device_id)
        .order_by(Location.timestamp.desc())
    ).first()

    if not location:
        raise HTTPException(status_code=404, detail="该设备没有定位信息")

    return {
        "device_id": device_id,
        "latitude": location.latitude,
        "longitude": location.longitude,
        "address": location.address,
        "timestamp": location.timestamp
    }


# 获取已安装应用数量
@app.get("/devices/{device_id}/apps")
def get_apps(
    device_id: int,
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session)
):
    decode_token(token)
    device = get_device_or_404(device_id, session)
    return {"device_id": device.id, "apps": device.apps}
