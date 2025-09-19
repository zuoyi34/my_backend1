from database import get_session_context
from models import User
from auth import get_password_hash

def create_admin():
    with get_session_context() as session:
        # 检查是否已经有管理员
        existing_admin = session.query(User).filter(User.is_admin == True).first()
        if existing_admin:
            print("⚠️ 已经存在管理员:", existing_admin.email)
            return

        admin = User(
            email="admin@example.com",
            full_name="Admin",
            is_active=True,
            is_admin=True,
            hashed_password=get_password_hash("admin123"),
        )
        session.add(admin)
        session.commit()
        print("✅ Admin created! (账号：admin@example.com  密码：admin123)")

if __name__ == "__main__":
    create_admin()
