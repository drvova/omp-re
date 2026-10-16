@echo off
rem Builds the shotgen demo fixture with w64devkit's gcc (adjust GCC to taste).
setlocal
set GCC=C:\Tools\w64devkit\bin\gcc.exe
cd /d "%~dp0"
if exist "%GCC%" (
  "%GCC%" -o fixture.exe fixture.c
) else (
  gcc -o fixture.exe fixture.c
)
exit /b %ERRORLEVEL%
