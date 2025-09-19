@echo off
cd /d C:\Users\ngwo5\Desktop\my_backend
uvicorn main:app --reload --host 127.0.0.1 --port 8000
pause
