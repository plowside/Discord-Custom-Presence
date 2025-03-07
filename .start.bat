@echo off
setlocal

:: Check if the script is running with administrator privileges
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo Running as administrator...
    Powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)


:: Change to the directory of the script
cd /d %~dp0


set VENV_DIR=venv

:: Check if the virtual environment exists
if not exist %VENV_DIR% (
    echo Virtual environment not found. Creating...
    python -m venv %VENV_DIR%
)

:: Check if the requirements.txt file exists
if exist requirements.txt (
    echo Checking installed dependencies from requirements.txt...

    venv\Scripts\pip freeze > installed_packages.txt
   
    :: Loop through each package in requirements.txt
    for /f "tokens=*" %%i in (requirements.txt) do (
        findstr /i "%%i" installed_packages.txt >nul
        if errorlevel 1 (
            echo Installing %%i...
            venv\Scripts\pip install %%i
        ) else (
            echo %%i is already installed.
        )
    )
)

:: Run the script to create a scheduled task
venv\Scripts\python.exe create_sheduled_task.py

endlocal
pause