@echo off
REM ✅ Batch script to run Best Fit Batch Autotune in Flattening mode for all data types.
REM This optimizes sequences by running Best Fit Autotune across multiple contenders.

REM ==============================
REM 🔹 Combined Input Processing
REM ==============================
echo Running Best Fit Batch Autotune for Flattening Mode (Combined Input)...
ACS.exe -RunCommand "run best fit Batch Autotune(-L3 -P0 -DC -MF)" -logMungeOutput -ExitJobComplete

REM ==============================
REM 🔹 Random Input Processing
REM ==============================
echo Running Best Fit Batch Autotune for Flattening Mode (Random Input)...
ACS.exe -RunCommand "run best fit Batch Autotune(-L3 -P0 -DR -MF)" -logMungeOutput -ExitJobComplete

REM ==============================
REM 🔹 Sequence Input Processing
REM ==============================
echo Running Best Fit Batch Autotune for Flattening Mode (Sequence Input)...
ACS.exe -RunCommand "run best fit Batch Autotune(-L3 -P0 -DS -MF)" -logMungeOutput -ExitJobComplete

REM ==============================
REM 🔹 Natural Input Processing
REM ==============================
echo Running Best Fit Batch Autotune for Flattening Mode (Natural Input)...
ACS.exe -RunCommand "run best fit Batch Autotune(-L3 -P0 -DN -MF)" -logMungeOutput -ExitJobComplete

echo All Flattening Best Fit Batch Autotune jobs are now running!
pause
