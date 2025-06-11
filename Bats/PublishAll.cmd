@echo off
setlocal enabledelayedexpansion

echo 🔄 Starting Mango project publishes...

REM Quote each project folder with spaces
set PROJECTS="Mango Workbench" "MangoAC" "MangoBM" "MangoZI"

REM Loop through each project safely
for %%P in (%PROJECTS%) do (
    set PROJECT=%%~P
    echo.
    echo 📦 Publishing !PROJECT!...
    pushd "!PROJECT!"
    
    dotnet publish -c Release -p:Platform=x64 -p:PublishProfile=FolderProfile
    if errorlevel 1 (
        echo ❌ Failed to publish !PROJECT!
    ) else (
        echo ✅ Successfully published !PROJECT!
    )
    
    popd
)

echo.
echo 🏁 All publish tasks completed.
endlocal
pause
