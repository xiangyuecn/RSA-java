@echo off

:Run
cls

javac -version
if errorlevel 1 (
	echo 需要安装JDK才能编译运行java文件
	goto Pause
)

javac -encoding utf-8 *.java

if not exist "com/github/xiangyuecn/rsajava" md "com/github/xiangyuecn/rsajava"
move *.class com/github/xiangyuecn/rsajava > nul

java com.github.xiangyuecn.rsajava.Test

set /p step=是否重新运行(y):
if "%step%"=="y" goto Run
goto End

:Pause
pause
:End