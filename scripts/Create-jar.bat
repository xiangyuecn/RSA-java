@echo off
::[zh_CN] 在Windows系统中双击运行这个脚本文件，自动完成java文件编译和打包成jar
::[en_US] Double-click to run this script file in the Windows system, and automatically complete the java file compilation and packaging into jar


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
cd ..\
call:echo2 "显示语言：简体中文    %cd%" "Language: English    %cd%"
echo.


call:echo2 "请输入需要生成的jar文件版本号：  " "Please enter the version number of the jar file to be generated:"
set step=&set /p jarVer=^> 


set srcDir=target\src
if exist %srcDir% rd /S /Q %srcDir% > nul
md %srcDir%
xcopy RSA_PEM.java %srcDir% /Y > nul
xcopy RSA_Util.java %srcDir% /Y > nul
cd %srcDir%


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
%jdkBinDir%javac -encoding utf-8 -cp "./*" RSA_PEM.java RSA_Util.java
if errorlevel 1 (
	echo.
	call:echo2 "Java文件编译失败  " "Java file compilation failed"
	goto Pause
)
cd ..\..

set dir=target\classes\com\github\xiangyuecn\rsajava
if exist target\classes rd /S /Q target\classes > nul
md %dir%
move %srcDir%\*.class %dir% > nul


call:echo2 "编译完成，正在生成jar..." "The compilation is complete, and the jar is being generated..."


set jarPath=target\rsa-java.lib-%jarVer%.jar
del %jarPath% /Q > nul 2>&1
if exist %jarPath% (
	echo.
	call:echo2 "无法删除旧文件：%jarPath%  " "Unable to delete old file: %jarPath%"
	goto Pause
)

set MANIFEST=target\classes\MANIFEST.MF
echo Manifest-Version: 1.0>%MANIFEST%
echo Info-Name: RSA-java>>%MANIFEST%
echo Info-Version: %jarVer%>>%MANIFEST%
echo Info-Build-Date: %date:~,10%>>%MANIFEST%
for /f "delims=" %%v in ('javac -version 2^>^&1') do (
	echo Info-Build-JDK: %%v>>%MANIFEST%
)
echo Info-Copyright: MIT, Copyright %date:~,4% xiangyuecn>>%MANIFEST%
echo Info-Repository: https://github.com/xiangyuecn/RSA-java>>%MANIFEST%

%jdkBinDir%jar cfm %jarPath% %MANIFEST% -C target/classes/ com
if errorlevel 1 (
	echo.
	call:echo2 "生成jar失败  " "Failed to generate jar"
	goto Pause
)
if not exist %jarPath% (
	echo.
	call:echo2 "未找到生成的jar文件：%jarPath%  " "Generated jar file not found: %jarPath%"
	goto Pause
)
echo.
call:echo2 "已生成jar，文件在源码根目录：%jarPath%，请copy这个jar到你的项目中使用。  " "The jar has been generated, and the file is in the root directory of the source code: %jarPath%, please copy this jar to use in your project."
echo.


:Pause
pause
:End