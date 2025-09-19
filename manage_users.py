import bcrypt
from sqlmodel import SQLModel, Session, create_engine, select
from sqlalchemy import Column, Integer, String, Boolean

from sqlmodel import SQLModel, Field

class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True, nullable=False, unique=True)
    full_name: str | None = None
    hashed_password: str
    is_active: bool = True
    is_admin: bool = False


# 数据库连接
engine = create_engine("sqlite:///./test.db", echo=False)

# 添加用户
def add_user(email: str, password: str, full_name: str = "", is_admin: bool = False):
    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    with Session(engine) as session:
        user = User(email=email, full_name=full_name, hashed_password=hashed_pw,
                    is_active=True, is_admin=is_admin)
        session.add(user)
        session.commit()
        print(f"✅ 添加用户成功: {email}")

# 删除用户
def delete_user(email: str):
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == email)).first()
        if not user:
            print(f"❌ 没找到用户: {email}")
            return
        session.delete(user)
        session.commit()
        print(f"🗑 已删除用户: {email}")

# 修改用户密码
def update_password(email: str, new_password: str):
    hashed_pw = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == email)).first()
        if not user:
            print(f"❌ 没找到用户: {email}")
            return
        user.hashed_password = hashed_pw
        session.add(user)
        session.commit()
        print(f"🔑 已修改 {email} 的密码")

# 查看用户
def list_users():
    with Session(engine) as session:
        users = session.exec(select(User)).all()
        print("📋 用户列表：")
        for u in users:
            print(f" - ID: {u.id}, 邮箱: {u.email}, 姓名: {u.full_name}, 管理员: {u.is_admin}, 激活: {u.is_active}")

# 主菜单
if __name__ == "__main__":
    print("=== 用户管理工具 ===")
    print("1. 查看用户")
    print("2. 添加用户")
    print("3. 删除用户")
    print("4. 修改密码")
    choice = input("请输入操作编号: ")

    if choice == "1":
        list_users()
    elif choice == "2":
        email = input("邮箱: ")
        password = input("密码: ")
        full_name = input("姓名(可选): ")
        is_admin = input("是否管理员? (y/n): ").lower() == "y"
        add_user(email, password, full_name, is_admin)
    elif choice == "3":
        email = input("要删除的邮箱: ")
        delete_user(email)
    elif choice == "4":
        email = input("邮箱: ")
        new_password = input("新密码: ")
        update_password(email, new_password)
    else:
        print("无效选择！")
