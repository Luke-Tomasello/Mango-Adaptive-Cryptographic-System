@echo off
echo ====================================
echo Resetting workspace...
echo ====================================

REM Remove read-only attribute and delete matching files recursively

echo Deleting Contenders,*.txt files...
for /r %%f in ("Contenders,*.txt") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting Contenders,*.gs? files...
for /r %%f in ("Contenders,*.gs?") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting CutList.json...
for /r %%f in ("CutList.json") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting GlobalSettings.json...
for /r %%f in ("GlobalSettings.json") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)


echo Deleting MangoConfig.txt...
for /r %%f in ("MangoConfig.txt") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)


echo Deleting TransformBenchmarkResults.*...
for /r %%f in ("TransformBenchmarkResults.*") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)


echo Deleting TransformProfileResults.json...
for /r %%f in ("TransformProfileResults.json") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting State,*.json...
for /r %%f in ("State,*.json") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting MungeFailDB,*.db and *.db-journal files...
for /r %%f in ("MungeFailDB,*.db") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)
for /r %%f in ("MungeFailDB,*.db-journal") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting BTRFailDB,*.db, *.db-journal, and -P6-DS-MC-SP.* files...
for /r %%f in ("BTRFailDB,*.db") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)
for /r %%f in ("BTRFailDB,*.db-journal") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)
for /r %%f in ("BTRFailDB,-P6-DS-MC-SP.*") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting BTRResults.txt files...
for /r %%f in ("BTRResults.txt") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting babymunge.txt files...
for /r %%f in ("babymunge.txt") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting foo.* files...
for /r %%f in ("foo.*") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting temp.* files...
for /r %%f in ("temp.*") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting custom.bin...
for /r %%f in ("custom.bin") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting ACS.* files...
for /r %%f in ("ACS.*") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting ACSConfig.txt...
for /r %%f in ("ACSConfig.txt") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting Frankenstein.*...
for /r %%f in ("Frankenstein.*") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting randoms.bin...
for /r %%f in ("randoms.bin") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Deleting UserData.bin...
for /r %%f in ("UserData.bin") do (
    if exist "%%~f" (
        echo Deleting %%~f
        attrib -r "%%~f"
        del /f /q "%%~f"
    )
)

echo Reset complete.
pause
