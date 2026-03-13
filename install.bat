@echo off
echo ========================================
echo Cyber Intelligence Analyzer - Setup
echo ========================================
echo.

echo Installing Python dependencies...
pip install -r requirements.txt

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to install dependencies
    echo Please make sure Python and pip are installed
    pause
    exit /b 1
)

echo.
echo ========================================
echo Installation completed successfully!
echo ========================================
echo.
echo To start the application, run:
echo     python app.py
echo.
echo Then open your browser to:
echo     http://localhost:5000
echo.
pause
