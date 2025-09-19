# 目录
# .env               # 环境变量（首次运行会自动生成示例）
# requirements.txt   # 依赖
# main.py            # 入口
# database.py        # 数据库连接
# models.py          # SQLModel 模型
# auth.py            # 认证与密码/JWT
# routers/users.py   # 用户管理（仅管理员）
# routers/items.py   # 业务示例（登录后可用）
# -------------------------------------------------

# ============================
# requirements.txt
# ============================
# fastapi
# uvicorn[standard]
# sqlmodel
# passlib[bcrypt]
# python-jose[cryptography]
# python-dotenv

# ============================
# .env（首次运行后如未生成，请手动创建）
# ============================
# SECRET_KEY=change-this-to-a-long-random-string
# ACCESS_TOKEN_EXPIRE_MINUTES=60
# DATABASE_URL=sqlite:///./app.db
# ADMIN_EMAIL=admin@example.com
# ADMIN_PASSWORD=admin123

# ============================
# database.py
# ============================
from sqlmodel import SQLModel, create_engine, Session
from os import getenv
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = getenv("DATABASE_URL", "sqlite:///./app.db")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, echo=False, connect_args=connect_args)

def get_session():
    with Session(engine) as session:
        yield session

# ============================
# models.py
# ============================
from typing import Optional
from sqlmodel import SQLModel, Field, Relationship
from datetime import datetime

class UserBase(SQLModel):
    email: str = Field(index=True, unique=True)
    full_name: Optional[str] = None
    is_active: bool = True
    is_admin: bool = False

class User(UserBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str
    items: list["Item"] = Relationship(back_populates="owner")
    created_at: datetime = Field(default_factory=datetime.utcnow)

class UserCreate(UserBase):
    password: str

class UserRead(UserBase):
    id: int
    created_at: datetime

class UserUpdate(SQLModel):
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None
    password: Optional[str] = None

class ItemBase(SQLModel):
    title: str
    description: Optional[str] = None

class Item(ItemBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    owner_id: int = Field(foreign_key="user.id")
    owner: Optional[User] = Relationship(back_populates="items")

class ItemCreate(ItemBase):
    pass

class ItemRead(ItemBase):
    id: int
    owner_id: int

# ============================
# auth.py
# ============================
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from os import getenv
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = getenv("SECRET_KEY", "changeme")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    sub: Optional[str] = None  # email


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = {"sub": subject, "iat": datetime.utcnow()}
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[TokenData]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return TokenData(sub=payload.get("sub"))
    except JWTError:
        return None

# ============================
# routers/users.py
# ============================
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import select, Session
from models import User, UserCreate, UserRead, UserUpdate
from database import get_session
from auth import get_password_hash, verify_password
from typing import List

router = APIRouter(prefix="/users", tags=["users"])


def require_admin(current_user: User):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")

@router.get("/", response_model=List[UserRead])
def list_users(current_user: User = Depends(require_current_user), session: Session = Depends(get_session)):
    require_admin(current_user)
    return session.exec(select(User)).all()

@router.post("/", response_model=UserRead)
def create_user(user_in: UserCreate, current_user: User = Depends(require_current_user), session: Session = Depends(get_session)):
    require_admin(current_user)
    if session.exec(select(User).where(User.email == user_in.email)).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=user_in.email, full_name=user_in.full_name, is_active=True, is_admin=user_in.is_admin or False, hashed_password=get_password_hash(user_in.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

@router.get("/{user_id}", response_model=UserRead)
def get_user(user_id: int, current_user: User = Depends(require_current_user), session: Session = Depends(get_session)):
    require_admin(current_user)
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.patch("/{user_id}", response_model=UserRead)
def update_user(user_id: int, user_in: UserUpdate, current_user: User = Depends(require_current_user), session: Session = Depends(get_session)):
    require_admin(current_user)
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    data = user_in.dict(exclude_unset=True)
    if "password" in data:
        user.hashed_password = get_password_hash(data.pop("password"))
    for k, v in data.items():
        setattr(user, k, v)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

@router.delete("/{user_id}")
def delete_user(user_id: int, current_user: User = Depends(require_current_user), session: Session = Depends(get_session)):
    require_admin(current_user)
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    session.delete(user)
    session.commit()
    return {"ok": True}

# ============================
# routers/items.py
# ============================
from fastapi import APIRouter, Depends, HTTPException
from typing import List
from sqlmodel import Session, select
from database import get_session
from models import Item, ItemCreate, ItemRead, User

router = APIRouter(prefix="/items", tags=["items"])

@router.get("/", response_model=List[ItemRead])
def list_items(current_user: User = Depends(require_current_user), session: Session = Depends(get_session)):
    return session.exec(select(Item).where(Item.owner_id == current_user.id)).all()

@router.post("/", response_model=ItemRead)
def create_item(item_in: ItemCreate, current_user: User = Depends(require_current_user), session: Session = Depends(get_session)):
    item = Item(**item_in.dict(), owner_id=current_user.id)
    session.add(item)
    session.commit()
    session.refresh(item)
    return item

@router.delete("/{item_id}")
def delete_item(item_id: int, current_user: User = Depends(require_current_user), session: Session = Depends(get_session)):
    item = session.get(Item, item_id)
    if not item or item.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Item not found")
    session.delete(item)
    session.commit()
    return {"ok": True}

# ============================
# main.py
# ============================
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import SQLModel, Session, select
from database import engine, get_session
from models import User, UserCreate, UserRead
from auth import create_access_token, verify_password, get_password_hash, Token
from routers import users as users_router
from routers import items as items_router
from os import getenv
from dotenv import load_dotenv

load_dotenv()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
app = FastAPI(title="后台 API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------- 依赖：当前用户 ---------
from jose import JWTError
from auth import decode_token

def require_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)) -> User:
    data = decode_token(token)
    if not data or not data.sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = session.exec(select(User).where(User.email == data.sub)).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")
    return user

app.dependency_overrides[users_router.require_current_user] = require_current_user
app.dependency_overrides[items_router.require_current_user] = require_current_user

# --------- 启动初始化 ---------
@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)
    # 初始化管理员
    admin_email = getenv("ADMIN_EMAIL", "admin@example.com")
    admin_password = getenv("ADMIN_PASSWORD", "admin123")
    with Session(engine) as session:
        existing = session.exec(select(User).where(User.email == admin_email)).first()
        if not existing:
            admin = User(email=admin_email, full_name="Admin", is_active=True, is_admin=True, hashed_password=get_password_hash(admin_password))
            session.add(admin)
            session.commit()

# --------- 公共路由 ---------
@app.post("/register", response_model=UserRead)
def register(user_in: UserCreate, session: Session = Depends(get_session)):
    if session.exec(select(User).where(User.email == user_in.email)).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=user_in.email, full_name=user_in.full_name, is_active=True, hashed_password=get_password_hash(user_in.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

@app.post("/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == form.username)).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    token = create_access_token(subject=user.email)
    return Token(access_token=token)

# --------- 业务路由挂载 ---------
app.include_router(users_router.router)
app.include_router(items_router.router)

# 运行： uvicorn main:app --reload --port 8000

# ============================
# 简易使用说明
# ============================
# 1) 创建虚拟环境并安装依赖：
#    python -m venv .venv && source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
#    pip install -r requirements.txt
# 2) 初始化环境变量（可选，默认见 .env 注释）：
#    cp .env.example .env  # 或自己创建 .env
# 3) 启动：
#    uvicorn main:app --reload --port 8000
# 4) 测试：
#    - 注册：POST /register {"email":"u@x.com","password":"123456"}
#    - 登录：POST /login x-www-form-urlencoded {username=email, password=密码} -> 返回 access_token
#    - 业务：携带 Authorization: Bearer <token> 调用 /items 与 /users
#    - 管理：使用 .env 中的 ADMIN_EMAIL/ADMIN_PASSWORD 登录，访问 /users 系列接口
# 5) 文档：
#    打开 http://127.0.0.1:8000/docs 交互式调试
