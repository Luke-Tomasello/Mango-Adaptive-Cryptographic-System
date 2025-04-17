:: L3_Grid_Search.cmd
:: ----------------------------------------------------
:: This script runs Mango L3 Munge with GR (Rounds) set to 1-9
:: for each data type {Natural, Random, Combined, Sequence}.
:: The goal is to benchmark performance and scoring across
:: varying GR settings.
:: ----------------------------------------------------

@echo off
setlocal enabledelayedexpansion

for %%N in (1 2 3 4 5 6 7 8 9) do (
    for %%T in (Natural Random Combined Sequence) do (
        echo Running GR=%%N with InputType=%%T...
        ACS.exe -Rounds %%N -RunCommand "run munge" -ExitJobComplete -maxSequenceLen 3 -inputType %%T -passCount 6 -quiet -useMetricScoring -mode Cryptographic -logMungeOutput
    )
)

echo All tasks completed.
pause
