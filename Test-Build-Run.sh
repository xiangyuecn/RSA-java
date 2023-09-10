#!/usr/bin/env bash
#[zh_CN] 在Linux、macOS系统终端中运行这个脚本文件，自动完成java文件编译和运行。需先安装了JDK，支持Java8(1.8)及以上版本
#如果你有BouncyCastle加密增强包（bcprov-jdk**-**.jar），请直接复制此jar文件到源码根目录，编译运行后即可获得全部加密签名模式支持

#[en_US] Run this script file in the terminal of Linux and macOS system to automatically compile and run java files. Need to install JDK first, support Java8 (1.8) and above
#If you have the BouncyCastle encryption enhancement package (bcprov-jdk**-**.jar), please copy this jar file directly to the source code root directory. After compiling and running, you can get support for all encryption signature modes.


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
echo2 "显示语言：简体中文    `pwd`" "Language: English    `pwd`"
function err(){
	if [ $isZh == 1 ]; then echo -e "\e[31m$1\e[0m";
	else echo -e "\e[31m$2\e[0m"; fi
}
function exit2(){
	if [ $isZh == 1 ]; then read -n1 -rp "请按任意键退出..." key;
	else read -n1 -rp "Press any key to exit..."; fi
	exit
}


jarPath=""
for f in `ls target/rsa-java.lib-*.jar 2>/dev/null`; do jarPath=$f; done
if [ "$jarPath" != "" ]; then
	echo2 "检测到已打包的jar：${jarPath}，是否使用此jar参与测试？(Y/N) N" "A packaged jar is detected: ${jarPath}, do you want to use this jar to participate in the test? (Y/N) N"
	read -rp "> " step
	if [ "${step^^}" != "Y" ]; then jarPath=""; fi
	if [ "$jarPath" != "" ]; then
		echo2 "jar参与测试：$jarPath" "jar participates in the test: $jarPath"
		echo 
	fi
fi

rootDir=rsaTest
echo 
echo2 "正在创Java项目${rootDir}..." "Creating Java project ${rootDir}..."
echo 
if [ ! -e $rootDir ]; then
	mkdir -p $rootDir
else
	rm ${rootDir}/* > /dev/null 2>&1
fi

if [ "$jarPath" == "" ]; then
	cp *.java $rootDir > /dev/null
else
	cp Test.java $rootDir > /dev/null
	cp $jarPath $rootDir > /dev/null
fi
if [ -e *.jar ]; then
	cp *.jar $rootDir > /dev/null
fi
cd $rootDir


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
${jdkBinDir}javac -encoding utf-8 -cp "./*" *.java
[ ! $? -eq 0 ] && {
	echo 
	err "Java文件编译失败" "Java file compilation failed";
	exit2;
}

dir="com/github/xiangyuecn/rsajava"
if [ ! -e $dir ]; then
	mkdir -p $dir
else
	rm ${dir}/*.class > /dev/null 2>&1
fi
mv *.class ${dir}

${jdkBinDir}java -cp "./:./*" com.github.xiangyuecn.rsajava.Test -cmd=1 -zh=${isZh}



