@echo off
cd /d "%~dp0"
where py >nul 2>&1
if %errorlevel%==0 (py -m pip install -r requirements.txt && py app.py) else (python -m pip install -r requirements.txt && python app.py)
pause
