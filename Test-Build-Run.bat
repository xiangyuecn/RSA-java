@echo off
::[zh_CN] 在Windows系统中双击运行这个脚本文件，自动完成java文件编译和运行。需先安装了JDK，支持Java8(1.8)及以上版本  
::如果你有BouncyCastle加密增强包（bcprov-jdk**-**.jar），请直接复制此jar文件到源码根目录，编译运行后即可获得全部加密签名模式支持  

::[en_US] Double-click to run this script file in Windows system to automatically compile and run the java file. JDK needs to be installed first, supporting Java8 (1.8) and above versions
::If you have the BouncyCastle encryption enhancement package (bcprov-jdk**-**.jar), please copy this jar file directly to the source code root directory. After compiling and running, you can get support for all encryption signature modes.


::[zh_CN] 修改这里指定需要使用的JDK（\结尾bin目录完整路径），否则将使用已安装的默认JDK  
::[en_US] Modify here to specify the JDK to be used (full path to the bin directory ending with \), otherwise the installed default JDK will be used
set jdkBinDir=
::set jdkBinDir=D:\xxxx\jdk-18_windows-x64_bin\jdk-18.0.2.1\bin\


cls
::chcp 437
set isZh=0
ver | find "版本%qjkTTT%" > nul && set isZh=1
goto Run
:echo2
	if "%isZh%"=="1" echo %~1
	if "%isZh%"=="0" echo %~2
	goto:eof

:Run
cd /d %~dp0
call:echo2 "显示语言：简体中文    %cd%" "Language: English    %cd%"
echo.


set jarPath=
for /f "delims=" %%f in ('dir /b target\rsa-java.lib-*.jar 2^>nul') do set jarPath=target\%%f
if "%jarPath%"=="" goto jarPath_End
	call:echo2 "检测到已打包的jar：%jarPath%，是否使用此jar参与测试？(Y/N) N  " "A packaged jar is detected: %jarPath%, do you want to use this jar to participate in the test? (Y/N) N"
	set step=&set /p step=^> 
	if /i not "%step%"=="Y" set jarPath=
	if not "%jarPath%"=="" (
		call:echo2 "jar参与测试：%jarPath%" "jar participates in the test: %jarPath%"
		echo.
	)
:jarPath_End

set rootDir=rsaTest
echo.
call:echo2 "正在创Java项目%rootDir%..." "Creating Java project %rootDir%..."
echo.
if not exist %rootDir% (
	md %rootDir%
) else (
	del %rootDir%\* /Q > nul
)

if "%jarPath%"=="" (
	xcopy *.java %rootDir% /Y > nul
) else (
	xcopy Test.java %rootDir% /Y > nul
	xcopy %jarPath% %rootDir% /Y > nul
)
if exist *.jar (
	xcopy *.jar %rootDir% /Y > nul
)
cd %rootDir%


if "%jdkBinDir%"=="" (
	call:echo2 "正在读取JDK版本（如需指定JDK为特定版本或目录，请修改本bat文件内jdkBinDir为JDK bin目录）：  " "Reading the JDK Version (if you need to specify the JDK as a specific version or directory, please modify the jdkBinDir in this bat file to the JDK bin directory):"
) else (
	call:echo2 "正在读取JDK（%jdkBinDir%）版本：  " "Reading JDK (%jdkBinDir%) Version:"
)


%jdkBinDir%javac -version
if errorlevel 1 (
	echo.
	call:echo2 "需要安装JDK才能编译运行java文件  " "JDK needs to be installed to compile and run java files"
	goto Pause
)

echo.
call:echo2 "正在编译Java文件..." "Compiling Java files..."
echo.
%jdkBinDir%javac -encoding utf-8 -cp "./*" *.java
if errorlevel 1 (
	echo.
	call:echo2 "Java文件编译失败  " "Java file compilation failed"
	goto Pause
)

set dir=com\github\xiangyuecn\rsajava
if not exist %dir% (
	md %dir%
) else (
	del %dir%\*.class > nul
)
move *.class %dir% > nul

%jdkBinDir%java -cp "./;./*" com.github.xiangyuecn.rsajava.Test -cmd=1 -zh=%isZh%

:Pause
pause
:End