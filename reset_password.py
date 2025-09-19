# reset_password.py
from sqlmodel import Session, select
from database import engine
from models import User
from auth import get_password_hash


def reset_password(identifier: str, new_password: str):
    """
    identifier 可以是 email 或 id
    """
    with Session(engine) as session:
        # 优先按 email 找
        user = session.exec(select(User).where(User.email == identifier)).first()

        # 如果没找到，就尝试按 id 找
        if not user and identifier.isdigit():
            user = session.get(User, int(identifier))

        if not user:
            print("用户不存在")
            return

        user.hashed_password = get_password_hash(new_password)
        session.add(user)
        session.commit()
        print(f"✅ 用户 {user.email} 密码已重置为 {new_password}")


if __name__ == "__main__":
    # 示例：修改管理员邮箱账号密码
    reset_password("admin@example.com", "newpassword123")

    # 示例：也可以用 id 修改
    # reset_password("1", "anotherpassword")
