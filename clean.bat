@echo off
setlocal

call :rmdir .\Win32
call :rmdir .\x64
call :rmdir .\Debug
call :rmdir .\Release

call :rmdir .\ovpn-cli\x64
call :rmdir .\ovpn-cli\Debug
call :rmdir .\ovpn-cli\Release

call :rmdir .\sdv
call :rmdir .\sdv.temp
call :rmdir .\codeql_db
call :rmfiles *.dvl.xml *.sarif codeql.build.bat
call :rmfiles *.log
goto :eof

:rmdir
if exist "%~1" rmdir "%~1" /s /q
goto :eof

:rmfiles
if "%~1"=="" goto :eof
if exist "%~1" del /f "%~1"
shift
goto rmfiles
