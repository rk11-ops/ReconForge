@echo off
setlocal
set ROOT=%~dp0
if exist "%ROOT%.venv\Scripts\python.exe" (
  "%ROOT%.venv\Scripts\python.exe" -m reconforge %*
) else (
  python -m reconforge %*
)
