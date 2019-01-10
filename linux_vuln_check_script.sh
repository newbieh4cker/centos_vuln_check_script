#!/bin/sh

# Coded by N3wbieH4cker
# bob3rdnewbie.tistory.com



# check priv
if [ "$EUID" -ne 0 ]
	then echo "root 권한으로 스크립트를 실행하여 주십시오."
	exit
fi


alias ls=ls
CF=`hostname`"_scan_result_"`date +%F__%T`.txt

echo > $CF 2>&1



echo "**********************************************************************"
echo "*                    리눅스 취약점 진단 스크립트                     *"
echo "**********************************************************************"
echo "*   항목에 따라 시간이 다른 항목에 비하여 다소 오래 걸릴수 있습니다  *"
echo "*   스캔 보고서는 hostname_scan_result_시각.txt  파일로 저장 됩니다  *"
echo "*   기준은 [주요 정보통신 기반 시설 취약점 분석,평가기준] 문서입니다 *"
echo "**********************************************************************"
echo ""

sleep 3


echo "**********************************************************************" >> $CF 2>&1
echo "*                           리눅스 스크립트                          *" >> $CF 2>&1
echo "**********************************************************************" >> $CF 2>&1
echo "" >> $CF 2>&1


echo "############################# 시작 시간 ##############################"
date


echo "############################# 시작 시간 ##############################"  >> $CF 2>&1
date >> $CF 2>&1


echo "============================  시스템  정보 ===========================" >> $CF 2>&1
echo >> $CF 2>&1

echo "1. 시스템 기본 정보" >> $CF 2>&1
echo "    운영체제	: " `head -n 1 /etc/centos-release` >> $CF 2>&1
echo "    호스트 이름	: " `uname -n` >> $CF 2>&1
echo "    커널 버전	: " `uname -r` >> $CF 2>&1
echo >> $CF 2>&1

echo "2. 네트워크 정보" >> $CF 2>&1
ifconfig -a >> $CF 2>&1
echo >> $CF 2>&1

echo 
echo
echo >> $CF 2>&1
echo >> $CF 2>&1

echo "************************** 취약점 체크 시작 **************************" 
echo


echo "************************** 취약점 체크 시작 **************************" >> $CF 2>&1
echo >> $CF 2>&1
echo >> $CF 2>&1


echo "============================== 계정 관리 =============================" 
echo "============================== 계정 관리 =============================" >> $CF 2>&1

echo "01. root 계정 원격 접속 제한"
echo "01. root 계정 원격 접속 제한" >> $CF 2>&1

if [ -z "`grep pts\? /etc/securetty`" ]
	then
		echo "    ==> [안전] 콘솔 로그인만 가능합니다" >> $CF 2>&1
	else
		echo "    ==> [취약] 콘솔 로그인 이외의 로그인이 가능합니다" >> $CF 2>&1
fi
echo >> $CF 2>&1
echo

echo "02. 패스워드 복합성 설정(및 정책)"
echo "02. 패스워드 복합성 설정(및 정책)" >> $CF 2>&1

echo "    ==> 알고리즘                :   `authconfig --test | grep hashing | awk '{print $5}'`" >> $CF 2>&1
echo "    ==> 최대 사용 기간          :   `cat /etc/login.defs | grep PASS_MAX_DAYS | awk '{print $2}' | sed '1d'`일" >> $CF 2>&1
echo "    ==> 최소 사용 시간          :   `cat /etc/login.defs | grep PASS_MIN_DAYS | awk '{print $2}' | sed '1d'`일" >> $CF 2>&1
echo "    ==> 최소 길이               :   `cat /etc/login.defs | grep PASS_MIN_LEN | awk '{print $2}' | sed '1d'`글자" >> $CF 2>&1
echo "    ==> 기간 만료 경고 기간(일) :   `cat /etc/login.defs | grep PASS_WARN_AGE | awk '{print $2}' | sed '1d'`일" >> $CF 2>&1
echo "    ==> 권장 정책 : 영문,숫자,특수문자를 조합하여 2종류 조합 시 10자리 이상, 3종류 이상 조합 시 8자리 이상(공공기간 9자리 이상)" >> $CF 2>&1

echo >> $CF 2>&1
echo


echo "03. 계정 잠금 (임계값) 설정"
echo "03. 계정 잠금 (임계값) 설정" >> $CF 2>&1

TI=`grep deny= /etc/pam.d/password-auth | awk '{print $5}' | awk -F = '{print $2}'`

if [ "`grep deny= /etc/pam.d/password-auth`" ]
	then
		echo "    ==> [현재] "$TI"번 로그인 실패시 계정이 잠김니다" >> $CF 2>&1
	else
		echo "    ==> [취약] 계정 잠금 정책이 설정되어 있지 않습니다" >> $CF 2>&1
	echo "    ==> [권장] 로그인 5회 이상 실패시 계정 잠" >> $CF 2>&1

fi

echo >> $CF 2>&1
echo


echo "04. 패스워드 파일 보호"
echo "04. 패스워드 파일 보호" >> $CF 2>&1

if [ "`cat /etc/passwd | grep "root" | awk -F: '{print $2}' | sed -n '1p'`" = x ]
	then
		if test -r /etc/shadow
			then
				echo "    ==> [안전] Shadow 패스워드 시스템을 사용중입니다" >> $CF 2>&1
			else
				echo "    ==> [취약] Passwd 패스워드 시스템을 사용중입니다" > $CF 2>&1
		fi
fi
echo >> $CF 2>&1




echo "  04-1. /etc/passwd" >> $CF 2>&1

PP=`ls -l /etc/passwd | awk {'print $1'}`
PO=`ls -l /etc/passwd | awk {'print $3'}`
PG=`ls -l /etc/passwd | awk {'print $4'}`

if [ $PP = -r--r--r--. ]
	then
		echo "    ==> [안전] 권한   : " $PP >> $CF 2>&1
else
	if [ $PP = -rw-r--r--. ]
		then
			echo "    ==> [안전] 권한   : " $PP >> $CF 2>&1
		else
			echo "    ==> [취약] 권한   : " $PP >> $CF 2>&1
	fi
fi

if [ $PO = root ]
	then
		echo "    ==> [안전] 소유자 : " $PO >> $CF 2>&1
	else
		echo "    ==> [취약] 소유자 : " $PO >> $CF 2>&1
fi

if [ $PG = root ]
	then
		echo "    ==> [안전] 그룹   : " $PO >> $CF 2>&1
	else
		echo "    ==> [취약] 그룹   : " $PO >> $CF 2>&1
fi

echo >> $CF 2>&1





echo "  04-2. /etc/shadow" >> $CF 2>&1

if test `ls -l /etc/shadow | awk {'print $1'} ` = -r--------.
	then
		echo "    ==> [안전] 권한   :  "`ls -l /etc/shadow | awk {'print $1'}` >> $CF 2>&1
else
	if test `ls -l /etc/shadow | awk {'print $1'} ` = ----------.
		then
			echo "    ==> [안전] 권한   :  "`ls -l /etc/shadow | awk {'print $1'}` >> $CF 2>&1
		else
			echo "    ==> [취약] 권한   :  "`ls -l /etc/shadow | awk {'print $1'}` >> $CF 2>&1
	fi
fi



if test `ls -l /etc/shadow | awk {'print $3'}` = root
	then
		echo "    ==> [안전] 소유자 : " `ls -l /etc/shadow | awk {'print $3'}` >> $CF 2>&1
	else
		echo "    ==> [취약] 소유자 : " `ls -l /etc/shadow | awk {'print $3'}` >> $CF 2>&1
fi


if test `ls -l /etc/shadow | awk {'print $4'} ` = root 
	then
		echo "    ==> [안전] 그룹   :  "`ls -l /etc/shadow | awk {'print $4'}` >> $CF 2>&1
	else
		echo "    ==> [취약] 그룹   :  "`ls -l /etc/shadow | awk {'print $4'}` >> $CF 2>&1
fi

echo >> $CF 2>&1
echo >> $CF 2>&1

echo
echo





echo "======================= 파일 및 디렉터리 관리 ========================" 
echo "======================= 파일 및 디렉터리 관리=========================" >> $CF 2>&1

echo "05. root홈, 패스 디렉터리 권한 및 패스 설정" 
echo "05. root홈, 패스 디렉터리 권한 및 패스 설정" >> $CF 2>&1
echo "    root 홈 디렉터리 : " `cat /etc/passwd | grep root | sed -n '1p' | awk -F: '{print $6}'` >> $CF 2>&1

GRDP=`cat /etc/passwd | grep root | sed -n '1p' | awk -F: '{print$6}' | ls -l /../ | awk '{print $1$9}' | grep root | awk -F. '{print $1}'`
RDP=dr-xr-x--- 

if test $GRDP=$RDP
	then
		echo "    ==>  [안전] root 홈 디렉터리 권한 : " $GRDP >> $CF 2>&1
	else
		echo "    ==>  [취약] root 홈 권한 : " $GRDP >> $CF 2>&1
fi

echo "    PATH 디렉터리 : " `env | grep PATH | awk -F= '{print $2}'` >> $CF 2>&1
echo
echo >> $CF 2>&1

echo "06. 파일 및 디렉터리 소유자 설정"
echo "06. 파일 및 디렉터리 소유자 설정" >> $CF 2>&1

if test -f `find / \( -nouser -o -nogroup \) -xdev -ls 2>/dev/null`
	then
		echo "    ==>  [안전] 소유자 혹은 그룹이 없는 파일 및 디렉터리가 존재하지 않습니다" >> $CF 2>&1
  else
		echo "    ==> [취약] 소유자 혹은 그룹이 없는 파일 및 디렉터리가 존재합니다" >> $CF 2>&1
fi



echo
echo >> $CF 2>&1

echo "07. /etc/passwd 파일 소유자 및 권한 설정"
echo "07. /etc/passwd 파일 소유자 및 권한 설정" >> $CF 2>&1
echo "    04-01 항목 참고" >> $CF 2>&1
echo
echo >> $CF 2>&1


echo "08. /etc/shadow 파일 소유자 및 권한 설정"
echo "08. /etc/shadow 파일 소유자 및 권한 설정" >> $CF 2>&1
echo "    04-02 항목 참고" >> $CF 2>&1
echo
echo >> $CF 2>&1

echo "09. /etc/hosts 파일 소유자 및 권한 설정"
echo "09. /etc/hosts 파일 소유자 및 권한 설정" >> $CF 2>&1

HO=`ls -l /etc/hosts | awk '{print $3}'`
HP=`ls -l /etc/hosts | awk '{print $1}'`

if [ $HO = root ]
	then
		echo "    ==> [안전] hosts 파일 소유자 : " $HO >> $CF 2>&1
	else
		echo "    ==> [취약] hosts 파일 소유자 : " $HO >> $CF 2>&1
fi

if [ $HP = -rw-------. ]
	then
		echo "    ==> [안전] hosts 파일 권한   : " $HP >> $CF 2>&1
	else
		echo "    ==> [취약] hosts 파일 권한   : " $HP >> $CF 2>&1
fi

echo
echo >> $CF 2>&1


echo "10. /etc/(x)inetd.conf 파일 소유자 및 권한 설정"
echo "10. /etc/(x)inetd.conf 파일 소유자 및 권한 설정" >> $CF 2>&1

if test -f /etc/inetd.conf
	then
		echo "    [OOOO] inetd.conf 파일이 존재합니다" >> $CF 2>&1
		IO=`ls -l /etc/inetd.conf | awk '{print $3}'`
		IP=`ls -l /etc/inetd.conf | awk '{print $1}'`

		if [ $IO = root ]
			then
				echo "    ==> [안전] inetd.conf 파일 소유자 : " $IO >> $CF 2>&1
			else
				echo "    ==> [취약] inetd.conf 파일 소유자 : " $IO >> $CF 2>&1
		fi

	if [ $IP = -rw-------. ]
		then
			echo "    ==> [안전] inetd.conf 파일 권한   : " $IP >> $CF 2>&1
		else
			echo "    ==> [취약] inetd.conf 파일 권한   : " $IP >> $CF 2>&1
	fi

else
	echo "    [XXXX] inetd.conf 파일이 존재하지 않습니다" >> $CF  2>&1
	echo >> $CF 2>&1
fi


if test -f /etc/xinetd.conf
	then
		echo "    [OOOO] xinetd.conf 파일이 존재합니다" >> $CF 2>&1
		XO=`ls -l /etc/xinetd.conf | awk '{print $3}'`
		XP=`ls -l /etc/xinetd.conf | awk '{print $1}'`

		if [ $XO = root ]
			then
				echo "    ==> [안전] xinetd.conf 파일 소유자 : " $XO >> $CF 2>&1
			else
				echo "    ==> [취약] xinetd.conf 파일 소유자 : " $XO >> $CF 2>&1
		fi

	if [ $XP = -rw-------. ]
		then
			echo "    ==> [안전] xinetd.conf 파일 권한   : " $XP >> $CF 2>&1
		else
			echo "    ==> [취약] xinetd.conf 파일 권한   : " $XP >> $CF 2>&1
	fi

else
	echo "    [XXXX] xinetd.conf 파일이 존재하지 않습니다" >> $CF 2>&1
	echo >> $CF 2>&1
fi

if [ -d "/etc/xinetd.d" ]
	then
		echo "    [OOOO] /etc/xinetd.d/ 폴더가 존재합니다" >> $CF 2>&1
		FP=`ls -l /etc/xinetd.d/ | awk '{print $1, $9}' | sed -n '1!p' | grep -v "^-rw-r--r--"`
		FO=`ls -l /etc/xinetd.d/ | awk '{print $3, $9}' | sed -n '1!p' | grep -v "^root"`
		
		if [ "$FP" ]
			then
				echo "    ==> [취약] 권한이 잘못 설정된 파일 있습니다. " >> $CF 2>&1
				echo "        > " $ FP
			else
				echo "    ==> [안전] 해당 폴더에 서비스 파일이 존재하지 않거나, 모든 파일이 올바른 권한으로 설정되어 있습니다." >> $CF 2>&1
		fi

		if [ "$FO" ]
			then
				echo "    ==> [취약] 소유자 잘못 설정된 파일 있습니다. " >> $CF 2>&1
				echo "        > " $ FO
			else
				echo "    ==> [안전] 해당 폴더에 서비스 파일이 존재하지 않거나, 모든 파일이 올바른 소유자로 설정되어 있습니다." >> $CF 2>&1
		fi

else
	echo "    [XXXX] /etc/xinetd.d 폴더가 존재하지 않습니다" >> $CF 2>&1	
fi

echo
echo >> $CF 2>&1

echo "11. /etc/(r)syslog.conf 파일 소유자 및 권한 설정"
echo "11. /etc/(r)syslog.conf 파일 소유자 및 권한 설정" >> $CF 2>&1


if test -f /etc/syslog.conf
	then
		echo "    [OOOO] syslog.conf 파일이 존재합니다" >> $CF 2>&1
		IO=`ls -l /etc/syslog.conf | awk '{print $3}'`
		IP=`ls -l /etc/syslog.conf | awk '{print $1}'`

		if [ $IO = root ]
			then
				echo "    ==> [안전] syslog.conf 파일 소유자 : " $IO >> $CF 2>&1
			else
				echo "    ==> [취약] syslog.conf 파일 소유자 : " $IO >> $CF 2>&1
		fi

	if [ $IP = -rw-r--r--. ]
		then
			echo "    ==> [안전] syslog.conf 파일 권한   : " $IP >> $CF 2>&1
		else
			echo "    ==> [취약] syslog.conf 파일 권한   : " $IP >> $CF 2>&1
	fi

else
	echo "    [XXXX] syslog.conf 파일이 존재하지 않습니다" >> $CF  2>&1
	echo >> $CF 2>&1
fi


if test -f /etc/rsyslog.conf
	then
		echo "    [OOOO] rsyslog.conf 파일이 존재합니다" >> $CF 2>&1
		XO=`ls -l /etc/rsyslog.conf | awk '{print $3}'`
		XP=`ls -l /etc/rsyslog.conf | awk '{print $1}'`

		if [ $XO = root ]
			then
				echo "    ==> [안전] rsyslog.conf 파일 소유자 : " $XO >> $CF 2>&1
			else
				echo "    ==> [취약] rsyslog.conf 파일 소유자 : " $XO >> $CF 2>&1
		fi

	if [ $XP = -rw-r--r--. ]
		then
			echo "    ==> [안전] rsyslog.conf 파일 권한   : " $XP >> $CF 2>&1
		else
			echo "    ==> [취약] rsyslog.conf 파일 권한   : " $XP >> $CF 2>&1
	fi

else
	echo "    [XXXX] rsyslog.conf 파일이 존재하지 않습니다" >> $CF 2>&1
fi

echo
echo >> $CF 2>&1

echo "12. /etc/services 파일 소유자 및 권한 설정"
echo "12. /etc/services 파일 소유자 및 권한 설정" >> $CF 2>&1

SO=`ls -l /etc/services | awk '{print $3}'`
SP=`ls -l /etc/services | awk '{print $1}'`

if [ $SO = root ]
	then
		echo "    ==> [안전] services 파일 소유자 : " $SO >> $CF 2>&1
	else
		echo "    ==> [취약] services 파일 소유자 : " $SO >> $CF 2>&1
fi

if [ $SP = -rw-r--r--. ]
	then
		echo "    ==> [안전] services 파일 권한   : " $SP >> $CF 2>&1
	else
		echo "    ==> [취약] services 파일 권한   : " $SP >> $CF 2>&1
fi

echo
echo >> $CF 2>&1

echo "13. SetUID, SetGID, Sticky Bit 설정 파일 검사"
echo "13. SetUID, SetGID, Sticky Bit 설정 파일 검사" >> $CF 2>&1

SF="13-1.SetUID.txt"
SG="13-2.SetGID.txt"
SB="13-3.Sticky_Bit.txt"

find / -user root -perm -4000 2>/dev/null > $SF 
find / -user root -perm -2000 2>/dev/null > $SG 
find / -user root -perm -1000 2>/dev/null > $SB

echo "    스캔 후 생성된 13-1, 13-2, 13-3.txt 파일을 참고하여 파일을 검사" >> $CF 2>&1

echo
echo >> $CF 2>&1

echo "14. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정"
echo "14. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정" >> $CF 2>&1

echo "    서버 환경마다 파일들이 다르기 때문에 이를 스크립트로 체크할 경우 오탐 발생이 높음" >> $CF 2>&1
echo "    따라서 수동적인 체크가 필요" >> $CF 2>&1
echo "    ==> [권장] 체크 후, 해당 파일이 root와 소유자만이 w 권한이 있도록 설정" >> $CF 2>&1
echo "    수동적인 체크 후, 해당 파일이  root와 소유자 이외에도 w 권한이 있다면 [취약]하다고 판단할 수 있음" >> $CF 2>&1
echo
echo >> $CF 2>&1

echo "15. world writable 파일 점검"
echo "15. world writable 파일 점검" >> $CF 2>&1
WW="15-1.World_Writable.txt"
find / -perm -2 -ls 2>/dev/null | awk {'print $3, $11'} > $WW
echo "    생성된 15-1.World_Writable.txt 및 보고서 파일 참조" >> $CF 2>&1
echo "    이 또한 서버 환경마다 다르기 때문에 수동적인 체크가 필요함" >> $CF 2>&1
echo "    다만 기본적으로 시스템에 설치되는 world writable 파일 자체가 상당히 많기 때문에, " >> $CF 2>&1
echo "    15-1.World_Writable.txt 목록(혹시 모를 악의적인 파일 포함)과 기본적으로 생성되는 world writable 파일 간의 비교가 필요함" >> $CF 2>&1
echo
echo >> $CF 2>&1

echo "16. /dev에 존재하지 않는 device 파일 점검"
echo "16. /dev에 존재하지 않는 device 파일 점검" >> $CF 2>&1
DF="16-1.Device_file.txt"
find /dev -type f -exec ls -l {} \; > $DF
echo "    생성된 16-1.Device_file.txt 및 보고서 파일 참조" >> $CF 2>&1
echo "    마찬가지로 서버의 환경마다 다르기 때문에 수동적인 체크가 필요함" >> $CF 2>&1
echo
echo >> $CF 2>&1

echo "17. $HOME/.rhosts, hosts.equiv 사용 금지"
echo "17. $HOME/.rhosts, hosts.equiv 사용 금지" >> $CF 2>&1

if test -f `ls -l $HOME/.rhosts 2>/dev/null`
	then
		if test -f `ls -l hosts.equiv 2>/dev/null`
			then
				echo "    ==> [안전] 해당 서비스가 활성화 되어 있지 않습니다" >> $CF 2>&1
			else
				echo "    ==> [취약] 해당 서비스가 활성화 되어 있습니다" >> $CF 2>&1
		fi
	else
		echo "    ==> [취약] 해당 서비스가 활성화 되어 있습니다" >> $CF 2>&1
fi
echo
echo >> $CF 2>&1

echo "18. 접속 IP 및 포트 제한"
echo "18. 접속 IP 및 포트 제한" >> $CF 2>&1
AL="18-1.hosts.allow.txt"
AD="18-2.hosts.deny.txt"
cat /etc/hosts.allow 2>/dev/null > $AL
cat /etc/hosts.deny > $AD

echo "    생성된 18-1.hosts.allow.txt, 18-2.hosts.deny.txt 참조" >> $CF 2>&1
echo "    allow는 서버에 접속을 허용할 IP 목록 및 서비스가 들어있음" >> $CF 2>&1
echo "    deny는  서버에 접속을 거부할 IP 목록 및 서비스가 들어있음" >> $CF 2>&1
echo "    일반적으로 deny 파일의 우선순위가 높음" >> $CF 2>&1
echo
echo >> $CF 2>&1
echo
echo >> $CF 2>&1


echo "============================= 서비스 관리 ============================" 
echo "============================= 서비스 관리 ============================" >> $CF 2>&1

echo "19. Finger 서비스 비활성화"
echo "19. Finger 서비스 비활성화" >> $CF 2>&1

if test -f /etc/xinetd.d/finger
	then
		if [ "`cat /etc/xinetd.d/finger  | grep disable | awk '{print $3}'`" = yes ]
			then
				echo "    ==> [안전] finger 서비스가 설치되어 있으나 비활성화 되어 있습니다" >> $CF 2>&1
			else
				echo "    ==> [취약] finger 서비스가 설치되어 있고, 활성화 되어 있습니다" >> $CF 2>&1
		fi
	else
		echo "    ==> [안전] finger 서비스가 설치되어 있지 않습니다" >> $CF 2>&1
fi

echo
echo >> $CF 2>&1

echo "20. Anonymous FTP 비활성화"
echo "20. Anonymous FTP 비활성화" >> $CF 2>&1

if test -f /etc/vsftpd/vsftpd.conf
	then
		if [ "`cat /etc/vsftpd/vsftpd.conf | grep anonymous_enable | awk -F= '{print $2}'`" = NO ]
			then
				echo "    ==> [안전] FTP에 익명 접속이 불가능합니다" >> $CF 2>&1
			else
				echo "    ==> [취약] FTP에 익명 접속이 가능합니다" >> $CF 2>&1
		fi
	else
		echo "    [XXXX] FTP 서비스가 설치되어 있지 않습니다" >> $CF 2>&1
fi

echo
echo >> $CF 2>&1

echo "21. r 계열 서비스 비활성화"
echo "21. r 계열 서비스 비활성화" >> $CF 2>&1

echo "    스크립트 상의 진단은 rlogin만 진행" >> $CF 2>&1
echo "    기타 r 계열 서비스 목록은 21-1. r_services.txt 에서 확인" >> $CF 2>&1

if test -f /etc/xinetd.d/rlogin
	then
		if [ "`cat /etc/xinetd.d/rlogin | grep disable | awk '{print $3}'`" = yes ]
			then
				echo "    ==> [안전] rlogin 서비스가 설치되어 있으나 비활성화 되어 있습니다" >> $CF 2>&1
			else
				echo "    ==> [취약] rlogin 서비스가 설치되어 있고, 활성화 되어 있습니다" >> $CF 2>&1
		fi
	else
		echo "    ==> [안전] rlogin 서비스가 설치되어 있지 않습니다" >> $CF 2>&1
fi

RS="21-1.r_services.txt"
ls /etc/xinetd.d/r* 2>/dev/null > $RS


echo
echo >> $CF 2>&1

echo "22. cron 파일 소유자 및 권한 설정"
echo "22. cron 파일 소유자 및 권한 설정" >> $CF 2>&1

if test -f /etc/cron.allow
	then
		echo "    [OOOO] cron.allow 파일이 존재합니다" >> $CF 2>&1	
		CO=`ls -l /etc/cron.allow | awk '{print $3}'`
		CP=`ls -l /etc/cron.allow | awk '{print $1}'`
	
		if [ $CO = root ]
			then
				echo "    ==> [안전] cron.allow 파일 소유자 : " $CO >> $CF 2>&1
			else
				echo "    ==> [취약] cron.allow 파일 소유자 : " $CO >> $CF 2>&1
		fi

		if [ $CP = -rw-------. ] 
			then
				echo "    ==> [안전] cron.allow 파일 권한   : " $CP >> $CF 2>&1
		
			else
				if [ $CP = -rw-r--r--. ]
					then
						echo "    ==> [안전] cron.allow 파일 권한   : " $CP >> $CF 2>&1
					else
						echo "    ==> [취약] cron.allow 파일 권한   : " $CP >> $CF 2>&1
				fi
		fi

else
	echo "    [XXXX] cron.allow 파일이 존재하지 않습니다" >> $CF 2>&1
	echo >> $CF 2>&1
fi


if test -f /etc/cron.deny
	then
		echo "    [OOOO] cron.deny 파일이 존재합니다" >> $CF 2>&1	
		CO=`ls -l /etc/cron.deny | awk '{print $3}'`
		CP=`ls -l /etc/cron.deny | awk '{print $1}'`
	
		if [ $CO = root ]
			then
				echo "    ==> [안전] cron.deny 파일 소유자 : " $CO >> $CF 2>&1
			else
				echo "    ==> [취약] cron.deny 파일 소유자 : " $CO >> $CF 2>&1
		fi

		if [ $CP = -rw-------. ]
			then
				echo "    ==> [안전] cron.deny 파일 권한   : " $CP >> $CF 2>&1
		
			else
				if [ $CP = -rw-r--r--. ]
					then
						echo "    ==> [안전] cron.deny 파일 권한   : " $CP >> $CF 2>&1
					else
						echo "    ==> [취약] cron.deny 파일 권한   : " $CP >> $CF 2>&1
				fi
		fi

else
	echo "    [XXXX] cron.deny 파일이 존재하지 않습니다" >> $CF 2>&1
	echo >> $CF 2>&1
fi

echo
echo >> $CF 2>&1


echo "23. DoS 공격에 취약한 서비스 비활성화"
echo "23. DoS 공격에 취약한 서비스 비활성화" >> $CF 2>&1
echo "    DoS 공격에 취약하다고 알려진 서비스들은 (echo, discard, daytime, chargen) 등이 있음" >> $CF 2>&1

ET=`cat /etc/xinetd.d/echo 2>/dev/null | grep disable | grep no`
DT=`cat /etc/xinetd.d/discard 2>/dev/null | grep disable | grep no`
TT=`cat /etc/xinetd.d/daytime 2>/dev/null | grep disable | grep no`
CT=`cat /etc/xinetd.d/chargen 2>/dev/null | grep disable | grep no`

if [[ -z $ET ]]
    then
        echo "    ==> [안전] echo    서비스가 설치되어 있지 않거나 비활성화 되어 있습니다." >> $CF 2>&1
    else
        echo "    ==> [취약] echo    서비스가 활성화 되어 있습니다" >> $CF 2>&1
fi

if [[ -z $DT ]]
	then
		echo "    ==> [안전] discard 서비스가 설치되어 있지 않거나 비활성화 되어 있습니다." >> $CF 2>&1
	else
		echo "    ==> [취약] discard 서비스가 활성화 되어 있습니다" >> $CF 2>&1
fi

if [[ -z $TT ]]
	then
		echo "    ==> [안전] daytime 서비스가 설치되어 있지 않거나 비활성화 되어 있습니다." >> $CF 2>&1
	else
		echo "    ==> [취약] daytime 서비스가 활성화 되어 있습니다" >> $CF 2>&1
fi


if [[ -z $CT ]]
	then
		echo "    ==> [안전] chargen 서비스가 설치되어 있지 않거나 비활성화 되어 있습니다." >> $CF 2>&1
	else
		echo "    ==> [취약] chargen 서비스가 활성화 되어 있습니다" >> $CF 2>&1
fi

echo
echo >> $CF 2>&1

echo "24. NFS 서비스 비활성화"
echo "24. NFS 서비스 비활성화" >> $CF 2>&1
NC=`ps -ef | egrep "nfs|statd|lockd" | sed '$d' | grep -v kblock`

if [ $NC ]
	then
		echo "   ==> [취약] NFS 서비스가 동작 중입니다." >> $CF 2>&1
		echo "        > " $NC

else
	echo "   ==> [안전] NFS 서비스가 동작 중이지 않습니다." >> $CF 2>&1
fi

echo
echo >> $CF 2>&1


echo "25. NFS 접근통제"
echo "25. NFS 접근통제" >> $CF 2>&1
echo "    24번 항목에서 NFS를 비활성화 하는 것을 권장하지만 사용해야 할 경우에는 적절한 접근통제가  필요함" >> $CF 2>&1
echo "    이 경우 관리자(=root)가 NFS 서비스를 설치하면서 공유 디렉터리를 임의로 지정하기 때문에 스크립트로 체크가 불가능" >> $CF 2>&1
echo "    ==> [권장] 해당 공유 디렉터리의 권한이 적절한지 수동으로 체크" >> $CF 2>&1
echo
echo >> $CF 2>&1


echo "26. automountd 제거"
echo "26. automountd 제거" >> $CF 2>&1
AM=`ps -ef | grep 'automount\|autofs' | sed '$d'`

if [ $AM ]
	then
		echo "   ==> [취약] NFS 서비스가 동작 중입니다." >> $CF 2>&1
		echo "        > " $AM

else
	echo "   ==> [안전] NFS 서비스가 동작 중이지 않습니다." >> $CF 2>&1
fi

echo
echo >> $CF 2>&1


echo "27. RPC 서비스 확인"
echo "27. RPC 서비스 확인" >> $CF 2>&1
echo "    다음과 같은 서비스를 제한 (단, 플랫폼에 따라 서비스 명이 다소 다를 수 있음)" >> $CF 2>&1
echo "    {sadmin, rpc.*, rquotad, shell. login. exec, talk, time, discard, chargen}" >> $CF 2>&1
echo "    {printer, uucp, echo, daytime, dtscpt, finger}" >> $CF 2>&1
echo >> $CF 2>&1
echo "    ==> [권장] 위싀 서비스들을 중지하거나, 최신 버전의 패치 적용" >> $CF 2>&1
echo "    위의 서비스들을 중지하거나, 최신 버전의 패치를 적용했을 경우 [안전] 하다고 판단" >> $CF 2>&1
echo "    위의 서비스들을 사용하거나, 최신 버전의 패치를 적용하지 않았을 경우 [취약] 하다고 판단" >> $CF 2>&1
echo
echo >> $CF 2>&1


echo "28. NIS, NIS+ 점검"
echo "28. NIS, NIS+ 점검" >> $CF 2>&1
echo "    관리자의 수동적인 점검이 필요함" >> $CF 2>&1
echo "    ==> [권장] NIS 보다 데이터 인증이 강화된 NIS+ 사용" >> $CF 2>&1
echo "    점검 후  NIS 보다 데이터 인증이 강화된 NIS+ 사용한다면 [안전] 하다고 판단" >> $CF 2>&1
echo "    점검 후 기본적인 NIS를 사용한다면 [취약] 하다고 판단" >> $CF 2>&1
echo
echo >> $CF 2>&1


echo "29. tftp, talk 서비스 비활성화"
echo "29. tftp, talk 서비스 비활성화" >> $CF 2>&1

TP=`cat /etc/xinetd.d/tftp 2>/dev/null | grep disable | grep no`
TK=`cat /etc/xinetd.d/talk 2>/dev/null | grep disable | grep no`

if [[ -z $TP ]]
    then
        echo "    ==> [안전] tftp 서비스가 설치되어 있지 않거나 비활성화 되어 있습니다." >> $CF 2>&1
    else
        echo "    ==> [취약] tftp 서비스가 활성화 되어 있습니다" >> $CF 2>&1
fi

if [[ -z $TK ]]
    then
        echo "    ==> [안전] talk 서비스가 설치되어 있지 않거나 비활성화 되어 있습니다." >> $CF 2>&1
    else
        echo "    ==> [취약] talk 서비스가 활성화 되어 있습니다" >> $CF 2>&1
fi

echo
echo >> $CF 2>&1


echo "30. Sendmail 버전 점검"
echo "30. Sendmail 버전 점검" >> $CF 2>&1
SI=`yum list installed | grep sendmail | awk '{print $1}'`

if [ $SI ]
	then
		SV=`echo \$Z | /usr/lib/sendmail -bt -d0 | sed -n '1p' | awk '{print $2}'`
		echo "    [OOOO] 설치된 sendmail의 버전은 $SV 입니다" >> $CF 2>&1
		echo "    ==> [권장] 최신 버전의 설치 및 업그레이드를 위해 sendmail 데몬의 중지가 필요하기 때문에 적절한 시간대에 수행해야 함" >> $CF 2>&1
	else
		echo "    [XXXX] sendmail이 설치되어 있지 않습니다 " >> $CF 2>&1
fi

echo
echo >> $CF 2>&1


echo "31. 스팸 메일 릴레이 제한"
echo "31. 스팸 메일 릴레이 제한" >> $CF 2>&1

if [ $SI ]
	then
		SP=`ls -l /etc/mail/access | awk '{print $1}'`
		if [ $SP ]
			then
				SP=`ls -l /etc/mail/access | awk '{print $1}'`
				echo "    ==> [안전] 스팸 메일 관련 설정 사항이 저장된 파일이 존재합니다" >> $CF 2>&1
				echo "    ==> [진행] 해당 파일을 DB화 시켜 sendmail 데몬에 인식시키는 작업을 수행합니다" >> $CF 2>&1
				makemap hash /etc/mail/access < /etc/mail/access
				echo "    ==> [완료] 작업을 완료하였습니다" >> $CF 2>&1
		else
				echo "    ==> [취약] 스팸 메일 관련 설정 사항이 명시 된 파일이 존재하지 않습니다" >> $CF 2>&1
		fi
	else
		echo "    [XXXX] sendmail이 설치되어 있지 않습니다" >> $CF 2>&1
fi

echo
echo >> $CF 2>&1


echo "32. 일반사용자의 Sendmail 실행 방지"
echo "32. 일반사용자의 Sendmail 실행 방지" >> $CF 2>&1

if [ $SI ]
	then
		SV=`cat /etc/mail/sendmail.cf | grep PrivacyOptions | awk -F= '{print $2}'`
		
		if [ $SV = authwarnings,novrfy,noexpn,restrictqrun ]
			then 
				echo "    ==> [안전] 일반사용자의 sendmail 실행 방지가 설정되어 있습니다" >> $CF 2>&1
			else
				echo "    ==> [취약] 일반사용자의 sendmail 실행 방지가 설정되어 있지 않습니다" >> $CF 2>&1
		fi
	else
		echo "    [XXXX] sendmail이 설치되어 있지 않습니다" >> $CF 2>&1
fi
echo
echo >> $CF 2>&1
		

echo "33. DNS 보안 버전 패치"
echo "33. DNS 보안 버전 패치" >> $CF 2>&1

DS=`dig +short @168.126.63.1 porttest.dns-oarc.net TXT | awk -Fis '{print $2}' | awk -F: {'print $1'} | sed '1d' | awk '{print $1}'`

if [ $DS=GOOD -o GREAT ]
	then
		echo "    ==> [안전] DNS 보안 패치가 최신 버전입니다" >> $CF 2>&1
	else
		echo "    ==> [취약] DNS 보안 패치가 구 버전입니다" >> $CF 2>&1
fi

echo
echo >> $CF 2>&1


echo "34. DNS Zone Transfer 설정"
echo "34. DNS Zone Transfer 설정" >> $CF 2>&1
echo "    Primary Name Server에는 Zone Transfer를 허용하는 서버를 지정" >> $CF 2>&1
echo "    Secondary Server 에는 Zone Transfer를 허용하지 않아야 함" >> $CF 2>&1
echo >> $CF 2>&1
echo "    ==> [권장] DNS Zone Transfer를 허가된 사용자에게만 허용해야 함" >> $CF 2>&1
echo "    DNS Zone Transfer를 모든 사용자에게 허용했을 경우 [취약] 하다고 판단" >> $CF 2>&1
echo
echo >> $CF 2>&1


echo "35. Apache 디렉터리 리스팅 제거"
echo "35. Apache 디렉터리 리스팅 제거" >> $CF 2>&1
AI=`yum list installed 2>/dev/null | grep httpd | awk '{print $1}'`

if [ "$AI" ]
	then
		GV=`cat /etc/httpd/conf/httpd.conf | grep Options | sed -n '1p'`

		if [[ $GV == *Indexes* ]]
			then
				echo "    ==> [취약] 디렉터리 리스팅이 설정되어 있습니다" >> $CF 2>&1
			else
				echo "    ==> [안전] 디렉터리 리스팅이 설정되어 있지 않습니다" >> $CF 2>&1
		fi
	else
		echo "    [XXXX] Apache 서비스가 설치되어 있지 않습니다 " >> $CF 2>&1
fi

echo
echo >> $CF 2>&1


echo "36. Apache 웹 프로세스 권한 제한"
echo "36. Apache 웹 프로세스 권한 제한" >> $CF 2>&1

if [ "$AI" ]
	then
		UP=`cat /etc/httpd/conf/httpd.conf | grep User | sed -n '3p' | awk '{print $2}'`
		GP=`cat /etc/httpd/conf/httpd.conf | grep Group | sed -n '3p' | awk '{print $2}'`

		if [ "$UP" != root ]
			then
				echo "    ==> [안전] 현재 설정된 웹 프로세스 User 권한  :" $UP >> $CF 2>&1
			else
				echo "    ==> [취약] 현재 설정된 웹 프로세스 User 권한  :" $UP >> $CF 2>&1
		fi

		if [ "$GP" != root ]
			then
				echo "    ==> [안전] 현재 설정된 웹 프로세스 Group 권한 :" $GP >> $CF 2>&1
			else
				echo "    ==> [취약] 현재 설정된 웹 프로세스 Group 권한 :" $GP >> $CF 2>&1
		fi
	else
		echo "    [XXXX] Apache 서비스가 설치되어 있지 않습니다 " >> $CF 2>&1
fi

echo
echo >> $CF 2>&1


echo "37. Apache 상위 디렉터리 접근 금지"
echo "37. Apache 상위 디렉터리 접근 금지" >> $CF 2>&1

if [ "$AI" ]
	then
		GC=`cat /etc/httpd/conf/httpd.conf  | grep AllowOverride | sed -n '1p' | awk '{print $2}'`

		if [ $GC = AuthConfig ]
			then
				echo "    ==> [안전] 디렉터리별 사용자 인증이 설정되어 있습니다" >> $CF 2>&1
				echo >> $CF 2>&1
				echo "    사용자 인증이 필요한 디렉터리에 다음의 지시자들이 포함된 .htaccess 파일 생성" >> $CF 2>&1
				echo "    ***************************************************************" >> $CF 2>&1
				echo "    *     지시자     *                     설명                  **" >> $CF 2>&1
				echo "    ***************************************************************" >> $CF 2>&1
				echo "    * AuthType       *  인증 형태 (Baisc / Digest)                *" >> $CF 2>&1
				echo "    * AuthName       *  인증 영역 (웹 브라우저의 인증창에 표시)   *" >> $CF 2>&1
				echo "    * AuthUserFile   *  사용자 패스워드 파일의 위치               *" >> $CF 2>&1
				echo "    * AuthGroupFile  *  그룹 파일의 위치 (옵션)                   *" >> $CF 2>&1
				echo "    * Require        *  접근을 허용할 사용자 / 그룹 정의          *" >> $CF 2>&1
				echo "    ***************************************************************" >> $CF 2>&1
				echo "    ***************************************************************" >> $CF 2>&1

				echo "    .htaccess 파일의 예제는 다음과 같음" >> $CF 2>&1
				echo "    ***************************************" >> $CF 2>&1
				echo "    # vi .htaccess" >> $CF 2>&1
				echo "      AuthType Basic" >> $CF 2>&1
				echo "      AuthName \"Welcome to AnonSE Server\"" >> $CF 2>&1
				echo "      AuthUserFile /etc/shadow" >> $CF 2>&1
				echo "      Require valid-user       " >> $CF 2>&1
				echo "    ***************************************" >> $CF 2>&1
			else
				echo "    ==> [취약]  디렉터리별 사용자 인증이 설정되어 있지 않습니다" >> $CF 2>&1
		fi
	else
		echo "    [XXXX] Apache 서비스가 설치되어 있지 않습니다 " >> $CF 2>&1
fi

echo
echo >> $CF 2>&1


echo "38. Apache 불필요한 파일 제거"
echo "38. Apache 불필요한 파일 제거" >> $CF 2>&1

if [ "$AI" ]
	then
		echo "    ==> [권장] 웹 서버를 정기적으로 검사하여 불필요한 파일을 제거" >> $CF 2>&1
		
	else
		echo "    [XXXX] Apache 서비스가 설치되어 있지 않습니다 " >> $CF 2>&1
fi

echo
echo >> $CF 2>&1


echo "39. Apache 링크 사용 금지"
echo "39. Apache 링크 사용 금지" >> $CF 2>&1

if [ "$AI" ]
	then
		GV=`cat /etc/httpd/conf/httpd.conf | grep Options | sed -n '1p'`

		if [[ $GV == *FollowSymLinks* ]]
			then
				echo "    ==> [취약] Apache 상에서 심볼릭 링크 사용이 설정되어 있습니다" >> $CF 2>&1
			else
				echo "    ==> [안전] Apache 상에서 심볼릭 링크 사용이 설정되어 있지 않습니다" >> $CF 2>&1
		fi
	else
		echo "    [XXXX] Apache 서비스가 설치되어 있지 않습니다 " >> $CF 2>&1
fi


echo
echo >> $CF 2>&1

echo "40. Apache 파일 업로드 및 다운로드 제한"
echo "40. Apache 파일 업로드 및 다운로드 제한" >> $CF 2>&1

if [ "$AI" ]
	then
		US=`cat /etc/php.ini 2>/dev/null |  grep post_max_size | awk '{print $3}'`
		DS=`cat /etc/httpd/conf/httpd.conf 2>/dev/null | grep LimitRequestBody`


		if [ $US ]
			then
				echo "    ==> [안전] 업로드 가능한 파일의 최대 용량   : "$US >> $CF 2>&1
			else
				echo "    ==> [취약] 업로드 가능한 파일의 최대 용량   : 제한없음" >> $CF 2>&1
		fi

		if [ $DS ]
			then
				echo "    ==> [안전] 다운로드 가능한 파일의 최대 용량 : "$DS >> $CF 2>&1
			else
				echo "    ==> [취약] 다운로드 가능한 파일의 최대 용량 : 제한없음" >> $CF 2>&1
		fi
		
	else
		echo "    [XXXX] Apache 서비스가 설치되어 있지 않습니다 " >> $CF 2>&1
fi

echo
echo >> $CF 2>&1

echo "41. Apache 웹 서비스 영역 분리"
echo "41. Apache 웹 서비스 영역 분리" >> $CF 2>&1


if [ "$AI" ]
	then
		DR=`cat /etc/httpd/conf/httpd.conf | grep DocumentRoot | sed -n '2p' | awk '{print $2}'`
		DD="/var/www/html"

		if [ $DR=$DD ]
			then
				echo "    ==> [취약] DocumentRoot에 설정된 디렉터리 : $DR" >> $CF 2>&1
			else
				echo "    ==> [안전] DocumentRoot에 설정된 디렉터리 : $DR" >> $CF 2>&1
		fi
		
	else
		echo "    [XXXX] Apache 서비스가 설치되어 있지 않습니다 " >> $CF 2>&1
fi

echo
echo
echo >> $CF 2>&1
echo >> $CF 2>&1


echo "============================== 패치 관리 ============================="
echo "============================== 패치 관리 =============================" >> $CF 2>&1

echo "42. 최신 보안패치 및 벤더 권고사항 적용"
echo "42. 최신 보안패치 및 벤더 권고사항 적용" >> $CF 2>&1
echo "    ==> [권장] 'yum update (-y)' 명령어를 사용하여 설치된 패키지의 최신 패치를 설치" >> $CF 2>&1
echo
echo
echo >> $CF 2>&1
echo >> $CF 2>&1


echo "============================== 로그 관리 ============================="
echo "============================== 로그 관리 =============================" >> $CF 2>&1
echo "43. 로그의 정기적 검토 및 보고"
echo "43. 로그의 정기적 검토 및 보고" >> $CF 2>&1
echo "    ==> [권장] 로그 기록에 대해 정기적 검토, 분석, 이에 대한 리포트 작성 및 보고" >> $CF 2>&1
echo
echo
echo >> $CF 2>&1
echo >> $CF 2>&1


echo "************************** 취약점 체크 종료 **************************" 
echo "************************** 취약점 체크 종료 **************************" >> $CF 2>&1
