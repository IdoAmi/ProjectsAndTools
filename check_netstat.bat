@echo off
if not exist "%USERPROFILE%\Desktop\newFolder" (
    mkdir "%USERPROFILE%\Desktop\newFolder"
)

netstat > "%USERPROFILE%\Desktop\newFolder\netstat_output.txt"
findstr ":80.*LISTENING" "%USERPROFILE%\Desktop\newFolder\netstat_output.txt" >nul

if errorlevel 1 (
    echo פורט 80 לא מאזין.
) else (
    echo פורט 80 מאזין.
)

pause
del "%USERPROFILE%\Desktop\newFolder\netstat_output.txt"
