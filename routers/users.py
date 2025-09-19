from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select
from database import get_session
from models import User, UserCreate, UserRead, UserLogin
from auth import create_access_token, verify_password, get_password_hash, get_current_user

router = APIRouter(prefix="/users", tags=["users"])


# ========== 普通功能 ==========
@router.post("/login")
def login(user_in: UserLogin, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == user_in.email)).first()
    if not user or not verify_password(user_in.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=UserRead)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


# ========== 管理员功能 ==========
def require_admin(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Only admins can manage users")
    return current_user


@router.get("/", response_model=list[UserRead])
def list_users(session: Session = Depends(get_session),
               current_user: User = Depends(require_admin)):
    return session.exec(select(User)).all()


@router.post("/", response_model=UserRead)
def create_user(user_in: UserCreate,
                session: Session = Depends(get_session),
                current_user: User = Depends(require_admin)):
    db_user = session.exec(select(User).where(User.email == user_in.email)).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        is_active=True,
        is_admin=user_in.is_admin if hasattr(user_in, "is_admin") else False
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return new_user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int,
                session: Session = Depends(get_session),
                current_user: User = Depends(require_admin)):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    session.delete(user)
    session.commit()
    return {"ok": True}
