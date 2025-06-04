@echo off
REM ✅ Batch script to run Mango for UserData input type only
REM 🔁 Toggle FailDB creation below (true/false)
set CREATE_FAIL_DB=false

REM ✅ Ensure -LN argument is provided
if "%~1"=="" (
    echo ❌ ERROR: You must specify the Munge level using -L1, -L2, ..., -L5, etc.
    echo Usage: RunBatch_UserData.cmd -L4
    exit /b 1
)

REM ✅ Extract sequence length from -L# argument (e.g., -L5 → 5)
set "LEVEL_FLAG=%~1"
set "SEQ_LEN=%LEVEL_FLAG:-L=%"

REM ✅ Validate SEQ_LEN is numeric
echo "%SEQ_LEN%" | findstr /R "[1-9][0-9]*" >nul || (
    echo ❌ ERROR: Invalid Munge level. Use format -L1, -L2, ..., -L5
    exit /b 1
)

set start=%TIME%

REM 🧠 Decide on the flag based on toggle
set FAILDB_FLAG=
if "%CREATE_FAIL_DB%"=="true" (
    set FAILDB_FLAG=-createMungeFailDB
)

REM ==============================
REM 🔹 UserData Input Processing
REM ==============================
echo Running L%SEQ_LEN% (FailDB: %CREATE_FAIL_DB%) for UserData Input...
Workbench.exe -RunCommand "run munge(--no-cutlist --remove-inverse)" -ExitJobComplete -maxSequenceLen %SEQ_LEN% -inputType UserData -passCount 6 -quiet -mode Cryptographic %FAILDB_FLAG%

REM 🕒 Calculate elapsed time
set end=%TIME%
for /F "tokens=1-4 delims=:.," %%a in ("%start%") do (
    set /A "startSec=(((%%a*60)+%%b)*60+%%c)"
)
for /F "tokens=1-4 delims=:.," %%a in ("%end%") do (
    set /A "endSec=(((%%a*60)+%%b)*60+%%c)"
)
set /A elapsedSec=endSec-startSec

echo Total elapsed time: %elapsedSec% seconds.
echo L%SEQ_LEN% UserData job (FailDB: %CREATE_FAIL_DB%) complete!
pause
