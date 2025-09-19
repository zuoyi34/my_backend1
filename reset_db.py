# reset_db.py
from sqlmodel import SQLModel
from database import engine

def reset_database():
    print("⚠️ 正在删除并重建所有表...")
    SQLModel.metadata.drop_all(engine)   # 删除所有表
    SQLModel.metadata.create_all(engine) # 重新创建表
    print("✅ 数据库已重置完成！")

if __name__ == "__main__":
    reset_database()
