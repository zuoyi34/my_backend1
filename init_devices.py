from sqlmodel import Session, select
from database import engine
from models import Device
from datetime import datetime

def init_devices():
    with Session(engine) as session:
        # 检查已有数据
        existing = session.exec(select(Device)).first()
        if existing:
            print("ℹ️ 已有设备数据，跳过初始化")
            return

        # 插入测试设备数据（关键是：加上 phone 和 device_id）
        devices = [
            Device(
                user_id=None,
                phone="13800000000",
                device_id="device001",
                ip="192.168.0.1",
                login_time=datetime.now(),
                contacts=10,
                sms=5,
                photos=20,
                apps=15
            ),
            Device(
                user_id=None,
                phone="13900000001",
                device_id="device002",
                ip="192.168.0.2",
                login_time=datetime.now(),
                contacts=0,
                sms=0,
                photos=0,
                apps=5
            ),
        ]

        for device in devices:
            session.add(device)
        session.commit()
        print("✅ 测试设备数据已插入")

if __name__ == "__main__":
    init_devices()
