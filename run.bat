@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 goto no_python

python -c "import sys" >nul 2>nul
if errorlevel 1 goto no_python

python -c "import PyQt5" >nul 2>nul
if errorlevel 1 goto install_deps

python main.py
if errorlevel 1 pause
exit /b 0

:install_deps
echo PyQt5 not found. Installing requirements...
python -m pip install -r requirements.txt
if errorlevel 1 goto install_failed
python main.py
if errorlevel 1 pause
exit /b 0

:no_python
echo Python 3.10+ was not found. Install Python and add it to PATH.
pause
exit /b 1

:install_failed
echo Failed to install PyQt5. Run: python -m pip install -r requirements.txt
pause
exit /b 1
