# reset_and_init_admin.py
from sqlmodel import SQLModel, Session, select
from database import engine
from models import User
from auth import get_password_hash
from os import getenv
from dotenv import load_dotenv

load_dotenv()

def reset_database():
    print("⚠️ 正在删除并重建所有表...")
    SQLModel.metadata.drop_all(engine)   # 删除所有表
    SQLModel.metadata.create_all(engine) # 重新创建表
    print("✅ 数据库已重置完成！")

def init_admin():
    admin_email = getenv("ADMIN_EMAIL", "admin")
    admin_password = getenv("ADMIN_PASSWORD", "admin123")

    with Session(engine) as session:
        existing = session.exec(select(User).where(User.email == admin_email)).first()
        if not existing:
            admin = User(
                email=admin_email,
                is_active=True,
                is_admin=True,
                hashed_password=get_password_hash(admin_password),
            )
            session.add(admin)
            session.commit()
            print(f"✅ 管理员账号已创建: {admin_email} / {admin_password}")
        else:
            print(f"ℹ️ 管理员账号已存在: {admin_email}")

if __name__ == "__main__":
    reset_database()
    init_admin()
