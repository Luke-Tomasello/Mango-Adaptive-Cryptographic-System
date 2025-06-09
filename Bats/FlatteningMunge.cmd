@echo off
REM ✅ Batch script to run Mango in Flattening mode for all data types.
REM This ensures data is fully neutralized before further transformations.

REM ==============================
REM 🔹 Combined Input Processing
REM ==============================
echo Running Flattening Mode for Combined Input...
ACS.exe -RunCommand "run munge" -ExitJobComplete -maxSequenceLen 3 -inputType Combined -passCount 0 -quiet -createFailDB  -useMetricScoring -mode Flattening  -flushThreshold 250000 -desiredContenders 1000

REM ==============================
REM 🔹 Random Input Processing
REM ==============================
echo Running Flattening Mode for Random Input...
ACS.exe -RunCommand "run munge" -ExitJobComplete -maxSequenceLen 3 -inputType Random -passCount 0 -quiet -createFailDB  -useMetricScoring -mode Flattening  -flushThreshold 250000 -desiredContenders 1000

REM ==============================
REM 🔹 Sequence Input Processing
REM ==============================
echo Running Flattening Mode for Sequence Input...
ACS.exe -RunCommand "run munge" -ExitJobComplete -maxSequenceLen 3 -inputType Sequence -passCount 0 -quiet -createFailDB  -useMetricScoring -mode Flattening  -flushThreshold 250000 -desiredContenders 1000

REM ==============================
REM 🔹 Natural Input Processing
REM ==============================
echo Running Flattening Mode for Natural Input...
ACS.exe -RunCommand "run munge" -ExitJobComplete -maxSequenceLen 3 -inputType Natural -passCount 0 -quiet -createFailDB  -useMetricScoring -mode Flattening  -flushThreshold 250000 -desiredContenders 1000

echo All Flattening Munge jobs are now running!
pause


