from sqlmodel import SQLModel, Session, select
from database import engine
from models import User, Device, Location, Contact, Message, Photo, App  # 导入所有模型
from auth import get_password_hash


def init_db():
    # 创建所有表（包括 User, Device, Location 等）
    SQLModel.metadata.create_all(engine)
    print("✅ 数据表已创建/检查完成")


def init_admin(email: str = "admin@example.com", password: str = "admin123"):
    with Session(engine) as session:
        existing = session.exec(select(User).where(User.email == email)).first()
        if existing:
            print(f"ℹ️ 管理员账号 {email} 已存在，跳过创建。")
            return

        admin = User(
            email=email,
            full_name="Admin",
            is_active=True,
            is_admin=True,
            hashed_password=get_password_hash(password),
        )
        session.add(admin)
        session.commit()
        print(f"✅ 管理员账号已创建: {email} / {password}")


if __name__ == "__main__":
    init_db()       # 先建表
    init_admin()    # 再创建管理员
