#!/usr/bin/env bash
#[zh_CN] 在Linux、macOS系统终端中运行这个脚本文件，自动完成java文件编译和打包成jar
#[en_US] Run this script file in the terminal of Linux and macOS system to automatically compile and package java files into jar


#[zh_CN] 修改这里指定需要使用的JDK（/结尾bin目录完整路径），否则将使用已安装的默认JDK
#[en_US] Modify here to specify the JDK to be used (full path to the bin directory ending with /), otherwise the installed default JDK will be used
jdkBinDir=""
#jdkBinDir="/home/download/jdk-19.0.1/bin/"


clear

isZh=0
if [ $(echo ${LANG/_/-} | grep -Ei "\\b(zh|cn)\\b") ]; then isZh=1; fi

function echo2(){
	if [ $isZh == 1 ]; then echo $1;
	else echo $2; fi
}
cd `dirname $0`
cd ../
echo2 "显示语言：简体中文    `pwd`" "Language: English    `pwd`"
echo 
function err(){
	if [ $isZh == 1 ]; then echo -e "\e[31m$1\e[0m";
	else echo -e "\e[31m$2\e[0m"; fi
}
function exit2(){
	if [ $isZh == 1 ]; then read -n1 -rp "请按任意键退出..." key;
	else read -n1 -rp "Press any key to exit..."; fi
	exit
}


echo2 "请输入需要生成的jar文件版本号：" "Please enter the version number of the jar file to be generated:"
read -rp "> " jarVer


srcDir="target/src"
if [ -e $srcDir ]; then rm -r $srcDir > /dev/null 2>&1; fi
mkdir -p $srcDir
cp RSA_PEM.java $srcDir
cp RSA_Util.java $srcDir
cd $srcDir


if [ "$jdkBinDir" == "" ]; then
	echo2 "正在读取JDK版本（如需指定JDK为特定版本或目录，请修改本sh文件内jdkBinDir为JDK bin目录）：" "Reading the JDK Version (if you need to specify JDK as a specific version or directory, please modify the jdkBinDir in this sh file to the JDK bin directory):"
else
	echo2 "正在读取JDK（${jdkBinDir}）版本：" "Reading JDK (${jdkBinDir}) Version:"
fi

${jdkBinDir}javac -version
[ ! $? -eq 0 ] && {
	echo 
	err "需要安装JDK才能编译运行java文件" "JDK needs to be installed to compile and run java files";
	exit2;
}

echo 
echo2 "正在编译Java文件..." "Compiling Java files...";
echo 
${jdkBinDir}javac -encoding utf-8 -cp "./*" RSA_PEM.java RSA_Util.java
[ ! $? -eq 0 ] && {
	echo 
	err "Java文件编译失败" "Java file compilation failed";
	exit2;
}
cd ../..

dir="target/classes/com/github/xiangyuecn/rsajava"
if [ -e target/classes ]; then rm -r target/classes > /dev/null 2>&1; fi
mkdir -p $dir
mv $srcDir/*.class $dir


echo2 "编译完成，正在生成jar..." "The compilation is complete, and the jar is being generated..."


jarPath="target/rsa-java.lib-${jarVer}.jar"
rm $jarPath > /dev/null 2>&1
[ -e $jarPath ] && {
	echo 
	err "无法删除旧文件：${jarPath}" "Unable to delete old file: ${jarPath}"
	exit2;
}

MANIFEST=target/classes/MANIFEST.MF
echo Manifest-Version: 1.0>$MANIFEST
echo Info-Name: RSA-java>>$MANIFEST
echo Info-Version: ${jarVer}>>$MANIFEST
echo Info-Build-Date: `date '+%Y-%m-%d'`>>$MANIFEST
echo Info-Build-JDK: `javac -version`>>$MANIFEST
echo Info-Copyright: MIT, Copyright `date '+%Y'` xiangyuecn>>$MANIFEST
echo Info-Repository: https://github.com/xiangyuecn/RSA-java>>$MANIFEST

${jdkBinDir}jar cfm $jarPath $MANIFEST -C target/classes/ com
[ ! $? -eq 0 ] && {
	echo 
	err "生成jar失败" "Failed to generate jar";
	exit2;
}
[ ! -e $jarPath ] && {
	echo 
	err "未找到生成的jar文件：${jarPath}" "Generated jar file not found: ${jarPath}";
	exit2;
}
echo 
echo2 "已生成jar，文件在源码根目录：${jarPath}，请copy这个jar到你的项目中使用。" "The jar has been generated, and the file is in the root directory of the source code: ${jarPath}, please copy this jar to use in your project."
echo 

exit2;
