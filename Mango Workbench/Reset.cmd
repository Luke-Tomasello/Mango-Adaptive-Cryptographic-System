@echo off
echo ====================================
echo 🔄 Resetting workspace...
echo ====================================

REM Remove read-only attribute and delete matching files recursively

echo 🗑️ Deleting Contenders,*.txt files...
for /r %%f in ("Contenders,*.txt") do (
    attrib -r "%%f"
    del /f /q "%%f"
)

echo 🗑️ Deleting Contenders,*.gs? files...
for /r %%f in ("Contenders,*.gs?") do (
    attrib -r "%%f"
    del /f /q "%%f"
)

echo 🗑️ Deleting CutList.json...
for /r %%f in ("CutList.json") do (
    attrib -r "%%f"
    del /f /q "%%f"
)

echo 🗑️ Deleting GlobalSettings.json...
for /r %%f in ("GlobalSettings.json") do (
    attrib -r "%%f"
    del /f /q "%%f"
)

echo 🗑️ Deleting MungeFailDB,*.db files...
for /r %%f in ("MungeFailDB,*.db") do (
    attrib -r "%%f"
    del /f /q "%%f"
)

echo 🗑️ Deleting MungeFailDB,*.db-journal files...
for /r %%f in ("MungeFailDB,*.db-journal") do (
    attrib -r "%%f"
    del /f /q "%%f"
)

echo 🗑️ Deleting State,*.json files...
for /r %%f in ("State,*.json") do (
    attrib -r "%%f"
    del /f /q "%%f"
)

echo 🗑️ Deleting ACS.* files...
for /r %%f in ("ACS.*") do (
    attrib -r "%%f"
    del /f /q "%%f"
)

echo 🗑️ Deleting ACSConfig.txt...
for /r %%f in ("ACSConfig.txt") do (
    attrib -r "%%f"
    del /f /q "%%f"
)

echo ✅ Reset complete.
pause
