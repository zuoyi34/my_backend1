from fastapi import Depends, HTTPException, status
from jose import jwt, JWTError
from sqlmodel import Session, select

from database import get_session
from models import User
from auth import oauth2_scheme, SECRET_KEY, ALGORITHM


def require_current_user(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
):
    # 解析 JWT
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 查数据库用户
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
