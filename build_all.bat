@echo off
setlocal

if "%CODEQL_HOME%"=="" set CODEQL_HOME=c:\codeql-home
set CODEQL_BIN=%CODEQL_HOME%\codeql\codeql.cmd

if "%EWDK11_DIR%"=="" set EWDK11_DIR=c:\ewdk11

call "%EWDK11_DIR%\BuildEnv\SetupBuildEnv.cmd"

set SOLUTION_FILE=ovpn-dco-win.sln
set DRIVER_PROJECT_FILE=ovpn-dco-win.vcxproj

for %%C in ( Release Debug ) do (
  for %%P in ( x64 x86 arm64 ) do (
    echo Building %SOLUTION_FILE%, configuration %%C, platform %%P
    call :runbuild %SOLUTION_FILE% %%C %%P
  )
)

if not "%BUILD_DISABLE_SDV%"=="" (
  echo Skipping SDV build because BUILD_DISABLE_SDV is set
  goto :end
)

for %%P in ( x64 x86 arm64 ) do (
  call :runsdv %DRIVER_PROJECT_FILE% "Release" %%P
  call :runql %DRIVER_PROJECT_FILE% "Release" %%P
  call :runca %DRIVER_PROJECT_FILE% "Release" %%P
  call :rundvl %DRIVER_PROJECT_FILE% "Release" %%P
)

:end:

if "%BUILD_FAILED%"=="1" exit /B 1
exit /B 0

:runbuild:
:: %1 - build file    (as "ovpn-dco-win.sln")
:: %2 - configuration (as "Release")
:: %3 - platform      (as x64)
msbuild.exe "%~1" /p:Configuration="%~2" /P:Platform=%3
goto :eof

:runsdv
echo Running SDV for %DRIVER_PROJECT_FILE%, configuration "%~2", platform %3
msbuild.exe "%~1" /t:clean /p:Configuration="%~2" /P:Platform=%3

IF ERRORLEVEL 1 (
  set BUILD_FAILED=1
)

msbuild.exe "%~1" /t:sdv /p:inputs="/clean" /p:Configuration="%~2" /P:Platform=%3

IF ERRORLEVEL 1 (
  set BUILD_FAILED=1
)

msbuild.exe "%~1" /t:sdv /p:inputs="/check /devenv" /p:Configuration="%~2" /P:Platform=%3

IF ERRORLEVEL 1 (
  set BUILD_FAILED=1
)

goto :eof

:runql

echo Running CodeQL for %DRIVER_PROJECT_FILE%, configuration "%~2", platform %3
echo "Removing previously created rules database"
rmdir /s/q codeql_db

echo call "%EWDK11_DIR%\BuildEnv\SetupBuildEnv.cmd" > %~dp1\codeql.build.bat
echo msbuild.exe "%~dp1\%~1" /t:rebuild /p:Configuration="%~2" /P:Platform=%3 >> %~dp1\codeql.build.bat

call %CODEQL_BIN% database create -l=cpp -s=%~dp1 -c "%~dp1\codeql.build.bat" %~dp1\codeql_db -j 0

IF ERRORLEVEL 1 (
  set CODEQL_FAILED=1
  set BUILD_FAILED=1
)

IF "%CODEQL_FAILED%" NEQ "1" (
  call %CODEQL_BIN% database analyze %~dp1\codeql_db windows_driver_recommended.qls --format=sarifv2.1.0 --output=%~dp1\%DRIVER_PROJECT_FILE%.sarif -j 0
)

IF ERRORLEVEL 1 (
  set BUILD_FAILED=1
)

goto :eof

:runca
echo Running Code Analysis for %DRIVER_PROJECT_FILE%, configuration "%~2", platform %3
msbuild.exe "%~1" /p:Configuration="%~2" /P:Platform=%3 /P:RunCodeAnalysisOnce=True

IF ERRORLEVEL 1 (
  set BUILD_FAILED=1
)

goto :eof

:rundvl
echo Creating Driver Verification Log for %DRIVER_PROJECT_FILE%, configuration "%~2", platform %3
msbuild.exe "%~1" /t:dvl /p:Configuration="%~2" /P:Platform=%3

IF ERRORLEVEL 1 (
  set BUILD_FAILED=1
)

goto :eof