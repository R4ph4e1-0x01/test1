#！/bin/bash

index=0       # 检测项编号
manual=0      # 需手工复核的检测项数
IP=`hostname -I | awk -F ' ' '{print $1}'`      # 获取IP地址
csvFile="$IP-Linux.csv"
echo "章节,子项,检查内容,检查结果,是否通过,备注" > "$csvFile"

# 账号口令-3.1.1：检查是否设置口令生存周期
passmax=`cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^#`
if [ -n "$passmax" ]; then
	checkRes=`echo $passmax | awk '{print $2}'`

	if [ "$checkRes" -gt 90 ]; then
		echo "3.1.1,,检查是否设置口令生存周期,密码最大过期天数：$checkRes,不符合规范" >> "$csvFile"
	else
		echo "3.1.1,,检查是否设置口令生存周期,密码最大过期天数：$checkRes,符合规范" >> "$csvFile"
	fi
else
	echo "3.1.1,,检查口令生存周期,未配置,不符合规范" >> "$csvFile"
fi


# 账号口令-3.1.2:检查是否设置口令最小长度 
passminlen=`cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^#`
if [ -n "$passminlen" ]; then
  checkRes=`echo $passminlen | awk '{print $2}'`
  if [ "$checkRes" -lt 8 ]; then
			echo "3.1.2,,检查是否设置口令最小长度,口令长度:$checkRes位,不符合规范" >> "$csvFile"
  else
			echo "3.1.2,,检查是否设置口令最小长度,口令长度:$checkRes位,符合规范" >> "$csvFile"
  fi
else
  echo "3.1.2,,检查是否设置口令最小长度,未配置,不符合规范" >> "$csvFile"
fi

# 账号口令-3.1.3:检查是否设置口令过期警告天数 
passwarn=`cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^#`
if [ -n "$passwarn" ]; then
  checkRes=`echo $passwarn | awk '{print $2}'`
  if [ "$checkRes" -lt 30 ]; then
			echo "3.1.3,,检查是否设置口令过期警告天数,口令过期警告天数:$checkRes天,不符合规范" >> "$csvFile"
  else
			echo "3.1.3,,检查是否设置口令过期警告天数,口令过期警告天数:$checkRes天,符合规范">> "$csvFile"
  fi
else
	echo "3.1.3,,检查是否设置口令过期警告天数,未配置,不符合规范" >> "$csvFile"
fi


# 账号口令-3.1.4:检查设备密码复杂度策略
if [ -f "/etc/pam.d/system-auth" ]; then
	flag=0
	info=`cat /etc/pam.d/system-auth | grep password | grep requisite`
	#line=`cat /etc/pam.d/system-auth | grep password | grep pam_cracklib.so | grep -v ^#`
	if [ -n "$info" ]; then
	    # minlen:密码字符串长度，dcredit数字字符个数，ucredit大写字符个数，ocredit特殊字符个数，lcredit小写字符个数
	    	#minlen=`echo $info | awk -F 'minlen=' '{print $2}' | awk -F ' ' '{print $1}'`
	    dcredit=`echo $info | awk -F 'dcredit=' '{print $2}' | awk -F '' '{print $2}'`
	    ucredit=`echo $info | awk -F 'ucredit=' '{print $2}' | awk -F '' '{print $2}'`
	    ocredit=`echo $info | awk -F 'ocredit=' '{print $2}' | awk -F '' '{print $2}'`
	    lcredit=`echo $info | awk -F 'lcredit=' '{print $2}' | awk -F '' '{print $2}'`
	    if [ -n "$dcredit" ] && [ -n "$ucredit" ] && [ -n "$lcredit" ] && [ -n "$ocredit" ]; then
	        flag=1
	    fi
	fi

	 # 以下检查/etc/security/pwquality.conf文件中的内容
	 # minlen为密码字符串长度，minclass为字符类别
	line_minlen=`cat /etc/security/pwquality.conf | grep minlen | grep -v ^#`
	line_minclass=`cat /etc/security/pwquality.conf | grep minclass | grep -v ^#`
	if [ -n "$line_minlen" ] && [ -n "$line_minclass" ]; then
		minlen=`echo "$line_minlen" | awk -F "=" '{print $2}' | awk '{gsub(/^\s+|\s+$/， "");print}'`
		minclass=`echo "$line_minclass" | awk -F "=" '{print $2}' | awk '{gsub(/^\s+|\s+$/， "");print}'`
		if [ "$minlen" -ge 8 ] && [ "$minclass" -ge 3 ];then
	    	flag=1
	    fi
	fi

	if [ "$flag" -eq 1 ]; then
		echo "3.1.4,,检查设备密码复杂度策略,dcredit=$dcredit  ucredit=$ucredit ocredit=$ocredit lcredit=$lcredit minlen=$minlen minclass=$minclass,符合规范" >> "$csvFile"
	else
		echo "3.1.4,,检查设备密码复杂度策略,dcredit=$dcredit  ucredit=$ucredit ocredit=$ocredit lcredit=$lcredit minlen=$minlen minclass=$minclass,不符合规范" >> "$csvFile"
	fi
else
	echo "3.1.4,,检查设备密码复杂度策略,,不符合规范,配置文件不存在此项仅支持CentOS7/RHEL7 " >> "$csvFile"
fi

# 口令策略-3.1.5 :检查是否存在空口令账号
tmp=`cat /etc/shadow | awk -F: '($2 == "" ) { print "user " $1 " does not have a password "}'`
if [ -z "$tmp" ]; then
  echo "3.1.5,,检查是否存在空口令账号,$tmp,符合规范" >> "$csvFile"
else
  echo "3.1.5,,检查是否存在空口令账号,$tmp,不符合规范" >> "$csvFile"
fi

# 帐号管理-3.1.6:检查是否设置除root之外UID为0的用户
result=`cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'`
if [ "root" = $result ]; then
	echo "3.1.6,,检查是否设置除root之外UID为0的用户,除root之外UID为0的用户:$result,符合规范" >> "$csvFile"
else
	echo "3.1.6,,检查是否设置除root之外UID为0的用户,除root之外UID为0的用户:$result,不符合规范" >> "$csvFile"
fi


# 认证授权-3.2.1:检查用户umask设置

echo "3.2.1" >> "$csvFile"
#设置flag=1，若有一项不合格，则flag=0
flag=1
umask1=`cat /etc/csh.cshrc | grep umask | awk -F 'umask' 'NR==1{print $2}'`
if [ "$umask1" -eq 077 ] || [ "$umask1" -eq 027 ]; then
	echo ",3.2.1.1,检查用户umask设置,/etc/csh.cshrc文件中umask:$umask1,符合规范" >> "$csvFile"
else
	echo ",3.2.1.1,检查用户umask设置,/etc/csh.cshrc文件中umask:$umask1,不符合规范" >> "$csvFile"
	flag=0
fi

umask2=`cat /etc/csh.login | grep umask`
if [ -n "$umask2" ]; then
	umask2_1=`echo "$umask2" | awk -F 'umask' 'NR==1{print $2}'`
	if [ "$umask2_1" -eq 077 ] || [ "$umask2_1" -eq 027 ]; then
	echo ",3.2.1.2,检查用户umask设置,/etc/csh.login文件中umask:$umask2_1,符合规范" >> "$csvFile"
	
	else
		echo ",3.2.1.2,检查用户umask设置,/etc/csh.login文件中umask:$umask2_1,不符合规范" >> "$csvFile"
		flag=0
	fi
else
	echo ",3.2.1.2,检查用户umask设置,,不符合规范,umask为空，请添加" >> "$csvFile"
	flag=0
fi

umask3=`cat /etc/bashrc | grep umask | awk -F 'umask' 'NR==2{print $2}' `
if [ "$umask3" -eq 077 ] || [ "$umask3" -eq 027 ]; then
	echo ",3.2.1.3,检查用户umask设置,/etc/bashrc 文件中umask:$umask3,符合规范" >> "$csvFile"
else
	echo ",3.2.1.3,检查用户umask设置,/etc/bashrc 文件中umask:$umask3,不符合规范" >> "$csvFile"
	flag=0
fi

umask4=`cat /etc/profile | grep umask | awk -F 'umask' 'NR==2{print $2}' `
if [ "$umask4" -eq 077 ] || [ "$umask4" -eq 027 ]; then
	echo ",3.2.1.4,检查用户umask设置,/etc/profile文件中umask:$umask4,符合规范" >> "$csvFile"
else
	echo ",3.2.1.4,检查用户umask设置,/etc/profile文件中umask:$umask4,不符合规范" >> "$csvFile"
	flag=0
fi


if [ "$flag" -eq 1 ]; then
	echo "3.2.1,,检查用户umask设置,所有子项均符合要求,符合规范" >> "$csvFile"
else
	echo "3.2.1,,检查用户umask设置,至少有一个子项不符合要求,不符合规范" >> "$csvFile"
fi

# 认证授权-3.2.2:检查重要目录或文件权限设置
echo "3.2.2" >> "$csvFile"

flag1=1
xineted_file="/etc/xineted.conf"
if [ -f "$xineted_file" ]; then
	xineted_stat=`stat -c %a /etc/xineted.conf`
	if [ "$xineted_stat" -ge 600 ]; then
		echo ",3.2.2.1,检查重要目录或文件权限设置,/etc/xineted.conf文件权限:$xineted_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.1,检查重要目录或文件权限设置,/etc/xineted.conf文件权限:$xineted_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.1,检查重要目录或文件权限设置,/etc/xineted.conf文件不存在,符合规范" >> "$csvFile"
fi

group_file="/etc/group"
if [ -f "$group_file" ]; then
	group_stat=`stat -c %a /etc/group`
	if [ "$group_stat" -ge 644 ]; then
		echo ",3.2.2.2,检查重要目录或文件权限设置,/etc/group文件权限:$group_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.2,检查重要目录或文件权限设置,/etc/group文件权限:$group_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.2,检查重要目录或文件权限设置,/etc/group文件不存在,符合规范" >> "$csvFile"

fi


shadow_file="/etc/shadow"
if [ -f "$shadow_file" ]; then
	shadow_stat=`stat -c %a /etc/shadow`
	if [ "$shadow_stat" -ge 400 ]; then
		echo ",3.2.2.3,检查重要目录或文件权限设置,/etc/shadow文件权限:$shadow_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.3,检查重要目录或文件权限设置,/etc/shadow文件权限:$shadow_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.3,检查重要目录或文件权限设置,/etc/shadow文件不存在,符合规范" >> "$csvFile"

fi

services_file="/etc/services"
if [ -f "$shadow_file" ]; then
	services_stat=`stat -c %a /etc/services`
	if [ "$services_stat" -ge 644 ]; then
		echo ",3.2.2.4,检查重要目录或文件权限设置,/etc/services文件权限:$services_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.4,检查重要目录或文件权限设置,/etc/services文件权限:$services_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.4,检查重要目录或文件权限设置,/etc/services文件不存在,符合规范" >> "$csvFile"

fi

security_file="/etc/security"
if [ -d "$security_file" ]; then
	security_stat=`stat -c %a /etc/security`
	if [ "$security_stat" -ge 600 ]; then
		echo ",3.2.2.5,检查重要目录或文件权限设置,/etc/security文件权限:$security_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.5,检查重要目录或文件权限设置,/etc/security文件权限:$security_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.5,检查重要目录或文件权限设置,/etc/security文件不存在,符合规范" >> "$csvFile"

fi

passwd_file="/etc/passwd"
if [ -f "$passwd_file" ]; then
	passwd_stat=`stat -c %a /etc/passwd`
	if [ "$passwd_stat" -ge 644 ]; then
		echo ",3.2.2.6,检查重要目录或文件权限设置,/etc/passwd文件权限:$passwd_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.6,检查重要目录或文件权限设置,/etc/passwd文件权限:$passwd_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.6,检查重要目录或文件权限设置,/etc/passwd文件不存在,符合规范" >> "$csvFile"

fi

rc6_file="/etc/rc6.d"
if [ -d "$rc6_file" ]; then
	rc6_stat=`stat -c %a /etc/rc6.d`
	if [ "$rc6_stat" -ge 750 ]; then
		echo ",3.2.2.7,检查重要目录或文件权限设置,/etc/rc6.d文件权限:$rc6_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.7,检查重要目录或文件权限设置,/etc/rc6.d文件权限:$rc6_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.7,检查重要目录或文件权限设置,/etc/rc6.d文件不存在,符合规范" >> "$csvFile"

fi

rc0_file="/etc/rc0.d"
if [ -d "$rc0_file" ]; then
	rc0_stat=`stat -c %a /etc/rc0.d`
	if [ "$rc0_stat" -ge 750 ]; then
		echo ",3.2.2.8,检查重要目录或文件权限设置,/etc/rc0.d文件权限:$rc0_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.8,检查重要目录或文件权限设置,/etc/rc0.d文件权限:$rc0_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.8,检查重要目录或文件权限设置,/etc/rc0.d文件不存在,符合规范" >> "$csvFile"

fi

rc1_file="/etc/rc1.d"
if [ -d "$rc1_file" ]; then
	rc1_stat=`stat -c %a /etc/rc1.d`
	if [ "$rc1_stat" -ge 750 ]; then
		echo ",3.2.2.9,检查重要目录或文件权限设置,/etc/rc1.d文件权限:$rc1_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.9,检查重要目录或文件权限设置,/etc/rc1.d文件权限:$rc1_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.9,检查重要目录或文件权限设置,/etc/rc1.d文件目录不存在,符合规范" >> "$csvFile"

fi

rc2_file="/etc/rc2.d"
if [ -d "$rc2_file" ]; then
	rc2_stat=`stat -c %a /etc/rc2.d`
	if [ "$rc2_stat" -ge 750 ]; then
		echo ",3.2.2.10,检查重要目录或文件权限设置,/etc/rc2.d文件权限:$rc2_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.10,检查重要目录或文件权限设置,/etc/rc2.d文件权限:$rc2_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.10,检查重要目录或文件权限设置,/etc/rc2.d文件目录不存在,符合规范" >> "$csvFile"

fi

etc_file="/etc"
if [ -d "$etc_file" ]; then
	etc_stat=`stat -c %a /etc`
	if [ "$etc_stat" -ge 750 ]; then
		echo ",3.2.2.11,检查重要目录或文件权限设置,/etc文件权限:$etc_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.11,检查重要目录或文件权限设置,/etc文件权限:$etc_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.11,检查重要目录或文件权限设置,/etc目录不存在,符合规范" >> "$csvFile"

fi

rc4_file="/etc/rc4.d"
if [ -d "$rc4_file" ]; then
	rc4_stat=`stat -c %a /etc/rc4.d`
	if [ "$rc4_stat" -ge 750 ]; then
		echo ",3.2.2.12,检查重要目录或文件权限设置,/etc/rc4.d文件权限:$rc4_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.12,检查重要目录或文件权限设置,/etc/rc4.d文件权限:$rc4_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.12,检查重要目录或文件权限设置,/etc/rc4.d目录不存在,符合规范" >> "$csvFile"

fi

rc5_file="/etc/rc5.d"
if [ -d "$rc5_file" ]; then
	rc5_stat=`stat -c %a /etc/rc5.d`
	if [ "$rc5_stat" -ge 750 ]; then
		echo ",3.2.2.13,检查重要目录或文件权限设置,/etc/rc5.d文件权限:$rc5_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.13,检查重要目录或文件权限设置,/etc/rc5.d文件权限:$rc5_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.13,检查重要目录或文件权限设置,/etc/rc5.d目录不存在,符合规范" >> "$csvFile"

fi

rc3_file="/etc/rc3.d"
if [ -d "$rc3_file" ]; then
	rc3_stat=`stat -c %a /etc/rc3.d`
	if [ "$rc3_stat" -ge 750 ]; then
		echo ",3.2.2.14,检查重要目录或文件权限设置,/etc/rc3.d文件权限:$rc3_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.14,检查重要目录或文件权限设置,/etc/rc3.d文件权限:$rc3_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.14,检查重要目录或文件权限设置,/etc/rc3.d文件目录不存在,符合规范" >> "$csvFile"

fi

init_file="/etc/rc.d/init.d"
if [ -d "$init_file" ]; then
	init_stat=`stat -c %a /etc/rc.d/init.d`
	if [ "$init_stat" -ge 750 ]; then
		echo ",3.2.2.15,检查重要目录或文件权限设置,/etc/rc.d/init.d文件权限:$init_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.15,检查重要目录或文件权限设置,/etc/rc.d/init.d文件权限:$init_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.15,检查重要目录或文件权限设置,/etc/rc.d/init.d文件目录不存在,符合规范" >> "$csvFile"

fi

tmp_file="/tmp"
if [ -d "$tmp_file" ]; then
	tmp_stat=`stat -c %a /tmp | grep -o --p '.{0,3}$'` 
	if [ "$tmp_stat" -ge 750 ]; then
		echo ",3.2.2.16,检查重要目录或文件权限设置,/tmp文件权限:$tmp_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.16,检查重要目录或文件权限设置,/tmp文件权限:$tmp_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.16,检查重要目录或文件权限设置,/tmp目录不存在,不符合规范" >> "$csvFile"

fi

grub_file="/etc/grub.conf"
if [ -d "$grub_file" ]; then
	grub_stat=`stat -c %a /etc/grub.conf`
	if [ "$grub_stat" -ge 600 ]; then
		echo ",3.2.2.17,检查重要目录或文件权限设置,/etc/grub.conf文件权限:$grub_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.17,检查重要目录或文件权限设置,/etc/grub.conf文件权限:$grub_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.17,检查重要目录或文件权限设置,/etc/grub.conf目录不存在,符合规范" >> "$csvFile"

fi

grub1_file="/etc/grub/grub.conf"
if [ -d "$grub1_file" ]; then
	grub1_stat=`stat -c %a /etc/grub/grub.conf`
	if [ "$grub1_stat" -ge 600 ]; then
		echo ",3.2.2.18,检查重要目录或文件权限设置,/etc/grub/grub.conf文件权限:$grub1_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.18,检查重要目录或文件权限设置,/etc/grub/grub.conf文件权限:$grub1_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.18,检查重要目录或文件权限设置,/etc/grub/grub.conf文件不存在,符合规范">> "$csvFile"

fi

lilo_file="/etc/lilo.conf"
if [ -d "$lilo_file" ]; then
	lilo_stat=`stat -c %a /etc/lilo.conf`
	if [ "$lilo_stat" -ge 600 ]; then
		echo ",3.2.2.19,检查重要目录或文件权限设置,/etc/lilo.conf文件权限:$lilo_stat,符合规范" >> "$csvFile"
	else
		echo ",3.2.2.19,检查重要目录或文件权限设置,/etc/lilo.conf文件权限:$lilo_stat,不符合规范" >> "$csvFile"
		flag1=0
	fi
else
	echo ",3.2.2.19,检查重要目录或文件权限设置,/etc/lilo.conf文件不存在,符合规范" >> "$csvFile"

fi

if [ "$flag1" -eq 1 ]; then
	echo "3.2.2,,检查重要目录或文件权限设置,所有子项均符合要求,符合规范" >> "$csvFile"
else
	echo "3.2.2,,检查重要目录或文件权限设置,至少有一个子项不符合要求,不符合规范" >> "$csvFile"
fi


# 认证授权-3.2.3:检查重要文件属性设置

echo "3.2.3" >> "$csvFile"
flag2=1
lsattr_pass=`lsattr /etc/passwd | awk '{ print $1 }' | awk -F- '{print $5}'`
lsattr1_pass=`lsattr /etc/passwd`
if [ "$lsattr_pass"x = "i"x  ]; then
  	echo ",3.2.3.1,检查重要文件属性设置,/etc/passwd文件属性:$lsattr_pass,符合规范" >> "$csvFile"
else
	echo ",3.2.3.1,检查重要文件属性设置,/etc/passwd文件属性:$lsattr_pass,不符合规范" >> "$csvFile"
  flag2=0
fi

lsattr_sha=`lsattr /etc/shadow | awk '{ print $1 }' | awk -F- '{print $5}'`
lsattr1_sha=`lsattr /etc/shadow`
if [ "$lsattr_sha"x = "i"x  ]; then
 	echo ",3.2.3.2,检查重要文件属性设置,/etc/shadow文件属性:$lsattr_sha,符合规范" >> "$csvFile"
else
	echo ",3.2.3.2,检查重要文件属性设置,/etc/shadow文件属性:$lsattr_sha,不符合规范" >> "$csvFile"
  flag2=0
fi

lsattr_gro=`lsattr /etc/group | awk '{ print $1 }' | awk -F- '{print $5}'`
lsattr1_gro=`lsattr /etc/group`
if [ "$lsattr_gro"x = "i"x  ]; then
  	echo ",3.2.3.3,检查重要文件属性设置,/etc/group文件属性:$lsattr_gro,符合规范" >> "$csvFile"
else
	echo ",3.2.3.3,检查重要文件属性设置,/etc/group文件属性:$lsattr_gro,不符合规范" >> "$csvFile"
  flag2=0
fi

lsattr_gsh=`lsattr /etc/gshadow | awk '{ print $1 }' | awk -F- '{print $5}'`
lsattr1_gsh=`lsattr /etc/gshadow`
if [ "$lsattr_gsh"x = "i"x  ]; then
  	echo ",3.2.3.4,检查重要文件属性设置,/etc/gshadow文件属性:$lsattr_gsh,符合规范" >> "$csvFile"
else
	echo ",3.2.3.4,检查重要文件属性设置,/etc/gshadow文件属性:$lsattr_gsh,不符合规范" >> "$csvFile"
  flag2=0
fi

if [ "$flag2" -eq 1 ]; then
	echo "3.2.3,,检查重要文件属性设置,所有子项均符合要求,符合规范" >> "$csvFile"
else
	echo "3.2.3,,检查重要文件属性设置,至少有一个子项不符合要求,不符合规范" >> "$csvFile"
fi

# 认证授权-3.2.4:检查用户目录缺省访问权限设置 
tmp=`cat /etc/login.defs | grep -i umask | grep -v ^#`
if [ -n "$tmp" ];then
	tt=`echo $tmp | awk -F " " {'print $2'}`
	if [ "$tt" -gt 27 ];then
		echo "3.2.4,,检查用户目录缺省访问权限设置,umask:$tt,符合规范" >> "$csvFile"
	else
		echo "3.2.4,,检查用户目录缺省访问权限设置,umask:$tt,不符合规范" >> "$csvFile"
	fi
else
	echo "3.2.4,,检查用户目录缺省访问权限设置,未配置,不符合规范" >> "$csvFile"
fi

# 认证授权-3.2.5:检查是否设置SSH登录前警告Banner
banner1=`cat /etc/ssh/sshd_config | grep Banner`
# 如果banner为空或者为 None，则符合要求
if [ -z "$banner1" ]; then
	echo "3.2.5,,检查是否设置SSH登录前警告Banner,Banner:$banner1,符合规范" >> "$csvFile"
else
  banner2=`cat /etc/ssh/sshd_config | grep Banner | awk '{print $2}' | grep -v "none"`
  if [ -n "$banner2" ]; then
	echo "3.2.5,,检查是否设置SSH登录前警告Banner,Banner:$banner2,符合规范" >> "$csvFile"
  else
	echo "3.2.5,,检查是否设置SSH登录前警告Banner,Banner:$banner1,不符合规范" >> "$csvFile"
  fi
fi

# 日志审计-3.3.1:检查是否配置远程日志功能
res=`cat /etc/rsyslog.conf | grep @ | grep -vE ^#`
if [ -n $res ];then
	echo "3.3.1,,检查是否配置远程日志功能,$res,符合规范" >> "$csvFile"
else
	echo "3.3.1,,检查是否配置远程日志功能,$res,不符合规范" >> "$csvFile"
fi

# 日志审计-3.3.2:检查安全事件日志配置
tmp=`cat /etc/rsyslog.conf | grep /var/log/messages | egrep '\*.info;mail.none;authpriv.none;cron.none' | grep -v ^#`
if [ -n "$tmp" ]; then
	echo "3.3.2,,检查安全事件日志配置,$tmp,符合规范" >> "$csvFile"	
else
	echo "3.3.2,,检查安全事件日志配置,$tmp,不符合规范" >> "$csvFile"
fi

# 日志审计-3.3.3:检查日志文件是否全局可写
echo "3.3.3" >> "$csvFile"

flag3=1

cron_file=`find /var/log/cron`
if [ -n "$cron_file" ]; then
	cron=`stat -c %a /var/log/cron`
	if [ "$cron" -ge 755 ]; then
		echo ",3.3.3.1,检查日志文件是否全局可写,/var/log/cron文件权限:$cron,符合规范" >> "$csvFile"
	else
		echo ",3.3.3.1,检查日志文件是否全局可写,/var/log/cron文件权限:$cron,不符合规范" >> "$csvFile"
		flag3=0
	fi
else
	echo ",3.3.3.1,检查日志文件是否全局可写,/var/log/cron文件不存在,符合规范" >> "$csvFile"
fi

secure_file=`find /var/log/secure`
if [ -n "$secure_file" ]; then
	secure=`stat -c %a /var/log/secure`
	if [ "$secure" -ge 755 ]; then
		echo ",3.3.3.2,检查日志文件是否全局可写,/var/log/secure文件权限:$secure,符合规范" >> "$csvFile"
	else
		echo ",3.3.3.2,检查日志文件是否全局可写,/var/log/secure文件权限:$secure,不符合规范" >> "$csvFile"
		flag3=0
	fi
else
	echo ",3.3.3.2,检查日志文件是否全局可写,/var/log/secure文件不存在,符合规范" >> "$csvFile"

fi

messages_file=`find /var/log/messages`
if [ -n "$messages_file" ]; then
	messages=`stat -c %a /var/log/messages`
	if [ "$messages" -ge 755 ]; then
		echo ",3.3.3.3,检查日志文件是否全局可写,/var/log/messages文件权限:$messages,符合规范" >> "$csvFile"
	else
		echo ",3.3.3.3,检查日志文件是否全局可写,/var/log/messages文件权限:$messages,不符合规范" >> "$csvFile"
		flag3=0
	fi
else
	echo ",3.3.3.3,检查日志文件是否全局可写,/var/log/messages文件不存在,符合规范" >> "$csvFile"

fi

boot_file=`find /var/log/boot.log`
if [ -n "$boot_file" ]; then
	boot=`stat -c %a /var/log/boot.log`
	if [ "$boot" -ge 755 ]; then
		echo ",3.3.3.4,检查日志文件是否全局可写,/var/log/boot.log文件权限:$boot,符合规范" >> "$csvFile"
	else
		echo ",3.3.3.4,检查日志文件是否全局可写,/var/log/boot.log文件权限:$boot,不符合规范" >> "$csvFile"
		flag3=0
	fi

else
	echo ",3.3.3.4,检查日志文件是否全局可写,/var/log/boot.log文件不存在,符合规范" >> "$csvFile"

fi


mail_file=`find /var/log/mail`
if [ -n "$mail_file" ]; then
	mail=`stat -c %a /var/log/mail`
	if [ "$mail" -ge 755 ]; then
		echo ",3.3.3.5,检查日志文件是否全局可写,/var/log/mail文件权限:$mail,符合规范" >> "$csvFile"
	else
		echo ",3.3.3.5,检查日志文件是否全局可写,/var/log/mail文件权限:$mail,不符合规范" >> "$csvFile"
		flag3=0
	fi
else
	echo ",3.3.3.5,检查日志文件是否全局可写,/var/log/mail文件不存在,符合规范" >> "$csvFile"

fi


localmessages_file=`find /var/log/localmessages`
if [ -n "$localmessages_file" ]; then
	localmessages=`stat -c %a /var/log/localmessages`
	if [ "$localmessages" -ge 755 ]; then
		echo ",3.3.3.6,检查日志文件是否全局可写,/var/log/localmessages文件权限:$localmessages,符合规范" >> "$csvFile"
	else
		echo ",3.3.3.6,检查日志文件是否全局可写,/var/log/localmessages文件权限:$localmessages,不符合规范" >> "$csvFile"
		flag3=0
	fi
else
	echo ",3.3.3.6,检查日志文件是否全局可写,/var/log/localmessages文件不存在,符合规范" >> "$csvFile"

fi


spooler_file=`find /var/log/spooler`
if [ -n "$spooler_file" ]; then
	spooler=`stat -c %a /var/log/spooler`
	if [ "$spooler" -ge 755 ]; then
		echo ",3.3.3.7,检查日志文件是否全局可写,/var/log/spooler文件权限:$spooler,符合规范" >> "$csvFile"
	else
		echo ",3.3.3.7,检查日志文件是否全局可写,/var/log/spooler文件权限:$spooler,不符合规范" >> "$csvFile"
		flag3=0
	fi
else
	echo ",3.3.3.7,检查日志文件是否全局可写,/var/log/spooler文件不存在,符合规范" >> "$csvFile"

fi

maillog_file=`find /var/log/maillog`
if [ -n "$maillog_file" ]; then
	maillog=`stat -c %a /var/log/maillog`
	if [ "$maillog" -ge 755 ]; then
		echo ",3.3.3.8,检查日志文件是否全局可写,/var/log/maillog文件权限:$maillog,符合规范" >> "$csvFile"
	else
		echo ",3.3.3.8,检查日志文件是否全局可写,/var/log/maillog文件权限:$maillog,不符合规范" >> "$csvFile"
		flag3=0
	fi
else
	echo ",3.3.3.8,检查日志文件是否全局可写,/var/log/maillog文件不存在,符合规范" >> "$csvFile"

fi


if [ "$flag3" -eq 1 ]; then
	echo "3.3.3,,检查日志文件是否全局可写,所有子项均符合要求,符合规范" >> "$csvFile"
else
	echo "3.3.3,,检查日志文件是否全局可写,至少有一个子项不符合要求,不符合规范" >> "$csvFile"
fi


# 日志审计-3.3.4:检查是否对登录进行日志记录
lasttmp=`last`
lastbtmp='lastb'

if [ -n "$lasttmp" ] && [ -n "$lastbtmp" ] ; then
	echo "3.3.4,,检查是否对登录进行日志记录,符合要求对登录日志进行了记录,符合规范" >> "$csvFile"
else
	echo "3.3.4,,检查是否对登录进行日志记录,不符合要求未对登录日志进行记录,不符合规范" >> "$csvFile"
fi

# 日志审计-3.3.5:检查是否配置su命令使用情况记录
#tmp='cat /etc/rsyslog.conf | grep /var/log/secure | egrep 'authpriv'.\('info|\*'\) | grep -v ^#'
tmp=`cat /etc/sudoers | grep -i /var/log/sudo.log | egrep -v ^\# `
if [ -n "$tmp" ]; then
	echo "3.3.5,,检查是否配置su命令使用情况记录,/etc/sudoers文件中配置项:$tmp,符合规范" >> "$csvFile"
else
	echo "3.3.5,,检查是否配置su命令使用情况记录,未配置$tmp,不符合规范" >> "$csvFile"
fi

# 协议安全-3.4.1:检查系统openssh安全配置
Protocol=`cat /etc/ssh/sshd_config | grep -i Protocol | egrep -v ^\# | awk '{print $2}'`
#PermitRootLogin=`cat /etc/ssh/sshd_config | grep -i PermitRootLogin | egrep -v ^\# | awk '{print $2}'`
#if [ "$PermitRootLogin" = "no" ] && [ "$Protocol" -eq 2 ]; then
if [ "$Protocol" -eq 2 ]; then
	echo "3.4.1,,检查系统openssh安全配置,已配置,符合规范" >> "$csvFile"
else
	echo "3.4.1,,检查系统openssh安全配置,未配置,不符合规范" >> "$csvFile"
fi


# 协议安全-3.4.2:检查是否修改SNMP默认团体字
snmp=`ps -ef|grep "snmpd"|grep -v "grep"`
if [ -z "$snmp" ]; then
	echo "3.4.2,,检查是否修改SNMP默认团体字,未使用,符合规范" >> "$csvFile"
else
  string=`cat /etc/snmp/snmpd.conf | grep com2sec  | grep public | grep -v ^# `
  if [ -n "$string" ]; then
		echo "3.4.2,,检查是否修改SNMP默认团体字,未配置,不符合规范" >> "$csvFile"
  else
		echo "3.4.2,,检查是否修改SNMP默认团体字,已配置,符合规范" >> "$csvFile"
  fi
fi

# 协议安全-3.4.3:检查使用ip协议远程维护的设备是否配置ssh协议，禁用telnet协议
res=`cat /etc/services | grep -E "telnet\s+23/tcp" | grep -E ^#`
if [ -n $res ];then
	echo "3.4.3,,禁用telnet协议,已配置,符合规范" >> "$csvFile"
else
	echo "3.4.3,,禁用telnet协议,未配置,不符合规范" >> "$csvFile"
fi

# 协议安全-3.4.4:检查是否禁止root用户登录FTP
tmp=`ps -ef | grep ftp | grep -v grep`
if [ -z "$tmp" ]; then
	echo "3.4.4,,检查是否禁止root用户登录FTP,无ftp,符合规范" >> "$csvFile"
else
  root=`cat /etc/vsftpd/ftpusers | grep root | grep -v ^#`
  if [ -n "$root" ]; then
		echo "3.4.4,,检查是否禁止root用户登录FTP,已禁用$root,符合规范" >> "$csvFile"
  else
		echo "3.4.4,,检查是否禁止root用户登录FTP,未禁用$root,不符合规范" >> "$csvFile"
  fi
fi


# 协议安全-3.4.5:检查是否禁止匿名用户登录FTP
tmp=`ps -ef | grep ftp | grep -v grep`
tmp1=`cat /etc/vsftpd/vsftpd.conf`
if [ -z "$tmp" ]; then
	echo "3.4.5,,检查是否禁止匿名用户登录FTP,无ftp$tmp,符合规范" >> "$csvFile"
else
  tmp=`cat /etc/vsftpd/vsftpd.conf | grep "anonymous_enable=NO" | grep -v ^#`
  if [ -z "$tmp" ]; then
	echo "3.4.5,,检查是否禁止匿名用户登录FTP,禁止匿名用户登录$tmp,不符合规范" >> "$csvFile"
  else
	echo "3.4.5,,检查是否禁止匿名用户登录FTP,未禁止匿名用户登录$tmp,符合规范" >> "$csvFile"
  fi
fi


# 其他配置-3.5.1:检查是否设置命令行界面超时退出
TMOUT1=`cat /etc/profile |grep -i TMOUT | grep -v ^#`
if [ -z "$TMOUT1" ]; then
	echo "3.5.1,,检查是否设置命令行界面超时退出,未设置命令行界面超时退出$TMOUT1,不符合规范" >> "$csvFile"
else
TMOUT=`cat /etc/profile |grep -i TMOUT | egrep -v ^\# | awk -F "=" '{print $2}'`
#echo "$TMOUT"
  if [ "$TMOUT" -gt 600 ]; then
	echo "3.5.1,,检查是否设置命令行界面超时退出,超时退出:$TMOUT大于600,不符合规范" >> "$csvFile"
  else
	echo "3.5.1,,检查是否设置命令行界面超时退出,超时退出:$TMOUT,符合规范" >> "$csvFile"
  fi
fi



# 其他配置-3.5.2:检查是否设置系统引导管理器密码
grub=`cat /boot/grub/menu.lst`
lilo=`cat /etc/lilo.conf`
grub_pass=`$grub | grep  password | grep -v ^#`
lilo_pass=`$lilo | grep  password | grep -v ^#`
if [ -n "$grub" ] || [ -n "$lilo" ]; then
	if [ -n "$grub_pass" ] || [ -n "$lilo_pass" ]; then
		echo "3.5.2,,检查是否设置系统引导管理器密码,系统引导器的类型是grub,符合规范" >> "$csvFile"
	else
		echo "3.5.2,,检查是否设置系统引导管理器密码,系统引导器的类型不是grub,不符合规范" >> "$csvFile"
	fi
else
	echo "3.5.2,,检查是否设置系统引导管理器密码,系统引导器的类型不是grub,不符合规范" >> "$csvFile"
fi

#if [ -n "$lilo" ]; then
#	if [ -n "$lilo_pass" ]; then
#		echo "3.5.2,,检查是否设置系统引导管理器密码,配置项:$lilo_pass,符合规范" >> "$csvFile"
#	else
#		echo "3.5.2,,检查是否设置系统引导管理器密码,系统引导器的类型不是grub,不符合规范" >> "$csvFile"
#	fi
#fi


# 其他配置-3.5.3:检查系统coredump设置
soft=`cat /etc/security/limits.conf | grep soft | grep core | grep 0 | grep ^*`
hard=`cat /etc/security/limits.conf | grep hard | grep core | grep 0 | grep ^*`
if [ -z "$soft" ] && [ -z "$hard" ]; then
	echo "3.5.3,,检查系统coredump设置,未配置,不符合规范" >> "$csvFile"
else
	echo "3.5.3,,检查系统coredump设置,配置:$soft、$hard,符合规范" >> "$csvFile"
fi

# 其他配置-3.5.4:检查历史命令设置
HISTSIZE=`cat /etc/profile | grep ^HISTSIZE | egrep -v ^\#`
HISTFILESIZE=`cat /etc/profile | grep ^HISTFILESIZE | egrep -v ^\#`
if [ -n "$HISTSIZE" ] && [ -n "$HISTFILESIZE" ]; then
  HISTSIZE=`cat /etc/profile | grep ^HISTSIZE | egrep -v ^\# | awk -F "=" '{print $2}'`
  HISTFILESIZE=`cat /etc/profile | grep ^HISTFILESIZE | egrep -v ^\# | awk -F "=" '{print $2}'`
  if [ "$HISTSIZE" -le 5 ] && [ "$HISTFILESIZE" -le 5 ]; then
	echo "3.5.4,,检查历史命令设置,配置:$HISTSIZE，$HISTFILESIZE,符合规范" >> "$csvFile"
  else
	echo "3.5.4,,检查历史命令设置,配置:$HISTSIZE，$HISTFILESIZE,不符合规范" >> "$csvFile"
  fi
else
	echo "3.5.4,,检查历史命令设置,未配置,不符合规范" >> "$csvFile"
fi

# 其他配置-3.5.5:检查是否使用PAM认证模块禁止wheel组之外的用户su为root
pam_rootok=`cat /etc/pam.d/su | grep auth | grep sufficient | grep pam_rootok.so | grep -v ^#`
pam_wheel=`cat /etc/pam.d/su | grep auth | grep pam_wheel.so | grep group=wheel | grep -v ^#`
if [ -n "$pam_rootok" ] && [ -n "$pam_wheel" ]; then
	echo "3.5.5,,检查是否使用PAM认证模块禁止wheel组之外的用户su为root,已配置,符合规范" >> "$csvFile"
else
	echo "3.5.5,,检查是否使用PAM认证模块禁止wheel组之外的用户su为root,未配置,不符合规范" >> "$csvFile"

fi


# 其他配置-3.5.6:检查是否对系统账户进行登录限制
res=`cat /etc/passwd | grep -v nologin | grep sh |awk -F: '{print $1}' | grep -E "daemon|bin|sys|adm|lp|uucp|nuucp|smmsp"`
if [ -z "$res" ];then
	echo "3.5.6,,检查是否对系统账户进行登录限制,已进行登录限制,符合规范" >> "$csvFile"
else
	echo "3.5.6,,检查是否对系统账户进行登录限制,$res等用户未登录限制,不符合规范" >> "$csvFile"
fi

# 其他配置-3.5.7:检查密码重复使用次数限制
if [ -f "/etc/pam.d/system-auth" ];then
	line=`cat /etc/pam.d/system-auth | grep password | grep sufficient | grep pam_unix.so | grep remember | grep -v ^#`
	if [ -n "$line" ]; then
	  times=`echo $line|awk -F "remember=" '{print $2}'`
	  if [ $times -ge 5 ]; then
		echo "3.5.7,,检查密码重复使用次数限制,次数:$times,符合规范" >> "$csvFile"
	  else
		echo "3.5.7,,检查密码重复使用次数限制,次数小于5次,不符合规范" >> "$csvFile"
	  fi
	else
		echo "3.5.7,,检查密码重复使用次数限制,未配置,不符合规范" >> "$csvFile"
	fi
#else
#	line=`cat /etc/pam.d/login | grep "deny" | grep "even_deny_root" | grep -v ^#`
#	if [ -n "$line" ];then
#		echo "3.5.7,,$line,符合规范" >> "$csvFile"
#	else
#		echo "3.5.7,$line,不符合规范" >> "$csvFile"
#	fi
fi


# 其他配置-3.5.8:检查账户认证失败次数限制
if [ -f "/etc/pam.d/system-auth" ];then
	res=`cat /etc/pam.d/system-auth | grep "deny=" | grep -v ^#`
	if [ -n "$res" ];then
		echo "3.5.8,,检查账户认证失败次数限制,已限制$res,符合规范" >> "$csvFile"
	else
		echo "3.5.8,,检查账户认证失败次数限制,未限制$res,不符合规范" >> "$csvFile"
	fi
else if [ -f "/etc/pam.d/passwd" ]; then
	res=`cat /etc/pam.d/passwd | grep "deny=" | grep -v ^#`
	if [ -n "$res" ];then
		echo "3.5.8,,检查账户认证失败次数限制,已限制$res,符合规范" >> "$csvFile"
	else
		echo "3.5.8,,检查账户认证失败次数限制,未限制$res,不符合规范" >> "$csvFile"
	fi
fi
fi


# 其他配置-3.5.9:检查是否关闭绑定多ip功能
multi=`cat /etc/host.conf | grep multi | grep -v ^#`
if [ -n "$multi" ]; then
	multi1=`echo $multi | grep off`
	if [ -n "$multi1" ]; then
		echo "3.5.9,,检查是否关闭绑定多ip功能,已关闭$multi1,符合规范" >> "$csvFile"
	else
		echo "3.5.9,,检查是否关闭绑定多ip功能,未关闭$multi1,不符合规范" >> "$csvFile"
	fi
else
	echo "3.5.9,,检查是否关闭绑定多ip功能,未配置,不符合规范" >> "$csvFile"
fi



# 其他配置-3.5.10:检查是否限制远程登录IP范围
res=`cat /etc/hosts.allow | grep allow | grep -v "^#"`
if [ -n "$res" ];then
	echo "3.5.10,,检查是否限制远程登录IP范围,已限制$res,符合规范" >> "$csvFile"
else
	echo "3.5.10,,检查是否限制远程登录IP范围,未限制$res,不符合规范" >> "$csvFile"
fi

# 其他配置-3.5.11:检查别名文件/etc/aliase

res1=`cat /etc/aliases | grep -E "games|toor|manager|root|system|ingres|uucp|dumper|operator|decode" | grep -v ^#`
res2=`cat /etc/mail/aliases | grep -E "games|toor|manager|root|system|ingres|uucp|dumper|operator|decode" | grep -v ^#`
if [ -n "$res1" ] && [ -n "$res2" ]; then
	echo "3.5.11,,检查别名文件/etc/aliase,有别名文件,不符合规范" >> "$csvFile"
else
	echo "3.5.11,,检查别名文件/etc/aliase,无别名文件,符合规范" >> "$csvFile"
fi



# 其他配置-3.5.12:检查拥有suid和sgid权限的文件

find=`find /usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp /usr/bin/write /usr/sbin/usernetctl /usr/sbin/traceroute /bin/mount /bin/umount /bin/ping /sbin/netreport -type f -perm +6000 2>/dev/null`
if [ -n "$find" ]; then
	echo "3.5.12,,检查拥有suid和sgid权限的文件,有拥有suid和sgid权限的文件,不符合规范,">> "$csvFile"
else
	echo "3.5.12,,检查拥有suid和sgid权限的文件,无拥有suid和sgid权限的文件,符合规范,">> "$csvFile"
fi


# 其他配置-3.5.13:检查是否配置定时自动屏幕锁定（适用于图形化界面）
flaglock=`gsettings get org.gnome.desktop.session idle-delay | awk -F " " '{print $2}'`
if [ "$flaglock" -gt 0 ]; then
	echo "3.5.13,,检查是否配置定时自动屏幕锁定（适用于图形化界面）,已配置屏幕锁定,符合规范" >> "$csvFile"
else
	echo "3.5.13,,检查是否配置定时自动屏幕锁定（适用于图形化界面）,未配置屏幕锁定,不符合规范" >> "$csvFile"
fi

## 其他配置-3.5.14:检查是否安装chkrootkit进行系统监测

#chkrootkit=`rpm -qa|grep -i "chkrootkit"`
#if [ -n "$chkrootkit" ]; then
#	echo "3.5.14,$chkrootkit,符合规范" >> "$csvFile"
#else
#	echo "3.5.14,$chkrootkit,不符合规范" >> "$csvFile"
#fi


# 其他配置-3.5.14:检查系统内核参数配置
tcp_syncookies=`cat /proc/sys/net/ipv4/tcp_syncookies`
if [ "$tcp_syncookies" -eq 1 ]; then
	echo "3.5.14,,检查系统内核参数配置,已配置$tcp_syncookies,符合规范" >> "$csvFile"
else
	echo "3.5.14,,检查系统内核参数配置,未配置$tcp_syncookies,不符合规范" >> "$csvFile"
fi


# 其他配置-3.5.15:检查是否按组进行账号管理
res=`cat /etc/passwd | grep -v "nologin" | awk -F ":" '{print $3==$4}' | grep 1 | wc -l`
if [ $res -ge 1 ];then
	echo "3.5.15,,检查是否按组进行账号管理,符合,符合规范" >> "$csvFile"
else
	echo "3.5.15,,检查是否按组进行账号管理,不符合,不符合规范" >> "$csvFile"
fi

# 其他配置-3.5.16:检查是否按用户分配账号
res=`ls /home | wc -l`
if [ $res -ge 2 ];then
	echo "3.5.16,,检查是否按用户分配账号,符合,符合规范" >> "$csvFile"
else
	echo "3.5.16,,检查是否按用户分配账号,不符合,不符合规范" >> "$csvFile"
fi

# 其他配置-3.5.17:检查root用户的path环境变量
tmp=`echo $PATH | egrep '\.\.'`
if [ -z "$tmp" ]; then
	echo "3.5.17,,检查root用户的path环境变量,符合,符合规范" >> "$csvFile"
else
	echo "3.5.17,,检查root用户的path环境变量,不符合,不符合规范" >> "$csvFile"
fi

# 其他配置-3.5.18:检查系统是否禁用Ctrl+Alt+Delete组合键
if [ -f "/usr/lib/systemd/system/ctrl-alt-del.target" ];then
	tmp=`cat /usr/lib/systemd/system/ctrl-alt-del.target | grep "Alias=ctrl-alt-del.target" | grep -v ^#`
	if [ -n "$tmp" ]; then
		echo "3.5.18,,检查系统是否禁用Ctrl+Alt+Delete组合键,未禁用,不符合规范" >> "$csvFile"
	else
		echo "3.5.18,,检查系统是否禁用Ctrl+Alt+Delete组合键,已禁用,符合规范" >> "$csvFile"
	fi
else
	echo "3.5.18,,检查系统是否禁用Ctrl+Alt+Delete组合键,未配置,符合规范" >> "$csvFile"
fi

# 其他配置-3.5.19:检查系统是否关闭系统信任机制
flag4=1
equiv=`find / -maxdepth 2 -name hosts.equiv`
rhosts=`find / -maxdepth 3 -type f -name .rhosts 2>/dev/null`
if [ -n "$equiv" ]; then
	echo ",3.5.19.1,检查系统是否关闭系统信任机制,未关闭,不符合规范" >> "$csvFile"
	flag4=0
else
	echo ",3.5.19.1,检查系统是否关闭系统信任机制,已关闭,符合规范" >> "$csvFile"
fi

if [ -n "$rhosts" ]; then
	echo ",3.5.19.2,检查系统是否关闭系统信任机制,未关闭,不符合规范" >> "$csvFile"
	flag4=0
else
	echo ",3.5.19.2,检查系统是否关闭系统信任机制,已关闭,符合规范" >> "$csvFile"
fi
if [ "$flag4" -eq 1 ]; then
	echo "3.5.19,,检查系统是否关闭系统信任机制,已关闭,符合规范" >> "$csvFile"
else
	echo "3.5.19,,检查系统是否关闭系统信任机制,未关闭,不符合规范" >> "$csvFile"
fi

# 其他配置-3.5.20:检查磁盘空间占用率

space=$(df -h | awk -F "[ %]+" 'NR!=1''{print $5}')
flag=0
for i in $space
do
  if [ $i -ge 80 ];then
    flag=1
  fi
done
if [ "$flag" -eq 1 ];then
  echo "3.5.20,,检查磁盘空间占用率,超过80%,不符合规范" >> "$csvFile"
else
  echo "3.5.20,,检查磁盘空间占用率,不超过80%,符合规范" >> "$csvFile"
fi


# 其他配置-3.5.21:检查是否删除了潜在危险文件
hasLocate=`whereis locate | awk -F " " '{print $2}'`
if [ -n "$hasLocate" ];then
	rhost=`locate .rhost | egrep 'rhost$'`
	netrc=`locate .netrc | egrep 'netrc$'`
	equiv=`locate .equiv | egrep 'hosts.equiv$'`
	if [ -z "$rhost" ] && [ -z "$netrc" ] && [ -z "$equiv" ]; then
		echo "3.5.21,,检查是否删除了潜在危险文件,无危险文件,符合规范" >> "$csvFile"
	else
		echo "3.5.21,,检查是否删除了潜在危险文件,危险文件:$rhost，$netrc，$equiv,不符合规范" >> "$csvFile"
	fi
else
	rhost=`find / -maxdepth 3 -name ".rhost"`
	netrc=`find / -maxdepth 3 -name ".netrc"`
	equiv=`find / -maxdepth 3 -name "hosts.equiv"`
	if [ -z "$rhost" ] && [ -z "$netrc" ] && [ -z "$equiv" ]; then
		echo "3.5.21,,检查是否删除了潜在危险文件,无危险文件,符合规范" >> "$csvFile"
	else
		echo "3.5.21,,检查是否删除了潜在危险文件,危险文件:$rhost，$netrc，$equiv,不符合规范" >> "$csvFile"
	fi
fi

# 其他配置-3.5.22:检查是否删除与设备运行，维护等工作无关的账号
res=`cat /etc/passwd | grep -v nologin | awk -F: '{print $1}' | grep -E "adm|lp|mail|uucp|operator|games|gopher|ftp|nobody|nobody4|noaccess|listen|webservd|rpm|dbus|avahi|mailnull|smmsp|nscd|vcsa|rpc|rpcuser|nfs|sshd|pcap|ntp|haldaemon|distcache|apache|webalizer|squid|xfs|gdm|sabayon|named"`
if [ -z "$res" ];then
	echo "3.5.22,,检查是否删除与设备运行，维护等工作无关的账号,没有无关账户$res,符合规范" >> "$csvFile"
else
	echo "3.5.22,,检查是否删除与设备运行，维护等工作无关的账号,有无关账户$res,不符合规范" >> "$csvFile"
fi

# 其他配置-3.5.23:检查是否配置用户所需最小权限
passwd=`stat -c %a /etc/passwd`
shadow=`stat -c %a /etc/shadow`
group=`stat -c %a /etc/group`

if [ "$passwd" -le 644 ] && [ "$shadow" -le 400 ] && [ "$group" -le 644 ]; then
	echo "3.5.23,,检查是否配置用户所需最小权限,符合要求$passwd，$shadow，$group,符合规范" >> "$csvFile"
else
	echo "3.5.23,,检查是否配置用户所需最小权限,不符合要求$passwd，$shadow，$group,不符合规范" >> "$csvFile"
fi


# 其他配置-3.5.24:检查是否关闭数据包转发功能

ip_forward=`sysctl -n net.ipv4.ip_forward`
if [ 0 -eq "$ip_forward" ]; then
	echo "3.5.24,,检查是否关闭数据包转发功能,已关闭$ip_forward,符合规范" >> "$csvFile"
else
	echo "3.5.24,,检查是否关闭数据包转发功能,未关闭$ip_forward,不符合规范" >> "$csvFile"
fi

# 其他配置-3.5.25:检查是否禁用不必要的系统服务

chkconf=`chkconfig --list | grep + | grep -vE "chargen-dgram|daytime-stream|echo-streamklogin|tcpmux-server|chargen-stream|discard-dgram|eklogin|krb5-telnet|tftp|cvs|discard-stream|ekrb5-telnet|kshell|time-dgram|daytime-dgram|echo-dgram|gssftp|rsync|time-stream"`
if [ -n "$chkconf" ]; then
 	echo "3.5.25,,检查是否禁用不必要的系统服务,已禁用$chkconf,符合规范" >> "$csvFile"
else
	echo "3.5.25,,检查是否禁用不必要的系统服务,未禁用$chkconf,不符合规范" >> "$csvFile"
fi  

# 其他配置-3.5.26:检查是否使用NTP（网络时间协议）保持时间同步

ntpd=`ps -ef|egrep "ntp|ntpd"|grep -v grep | grep "/usr/sbin/ntpd"`
if [ -n "$ntpd" ]; then
  server=`cat /etc/ntp.conf | grep ^server`
  if [ -n "$server" ]; then
	echo "3.5.26,,检查是否使用NTP（网络时间协议）保持时间同步,已同步,符合规范" >> "$csvFile"
  else
	echo "3.5.26,,检查是否使用NTP（网络时间协议）保持时间同步,未同步,不符合规范" >> "$csvFile"
  fi
else
	echo "3.5.26,,检查是否使用NTP（网络时间协议）保持时间同步,未开启,符合规范" >> "$csvFile"
fi

# 其他配置-3.5.27:检查NFS（网络文件系统）服务配置
tmp=`netstat -lntp | grep nfs`
if [ -z "$tmp" ]; then
	echo "3.5.27,,检查NFS（网络文件系统）服务配置,未开启服务$tmp,符合规范" >> "$csvFile"
else
  allow=`cat /etc/hosts.allow | grep -v ^#`
  deny=`cat /etc/hosts.deny | grep -v ^#`
  if [ -n "$allow" ] && [ -n "$deny" ]; then
	echo "3.5.27,,检查NFS（网络文件系统）服务配置,未配置$allow $deny, 不符合规范" >> "$csvFile"
  fi
fi

# 其他配置-3.5.28:检查是否安装OS补丁
os=`uname -a`
echo "3.5.28,,检查是否安装OS补丁,内核版本:$os,符合规范,需手工检查" >> "$csvFile"

# 其他配置-3.5.29:检查是否设置SSH成功登录后Banner

#systemctl is centos7 or redhat 7 
#tmp=`systemctl status sshd | grep running`
tmp=`service sshd status | grep running`
if [ -z "$tmp" ]; then
	echo "3.5.29,,检查是否设置SSH成功登录后Banner,未开启服务$tmp,符合规范" >> "$csvFile"
else
  temp=`cat /etc/motd`
  if [ -n "$temp" ]; then
		echo "3.5.29,,检查是否设置SSH成功登录后Banner,Banner信息:$tmp,," >> "$csvFile"
  else
		echo "3.5.29,,检查是否设置SSH成功登录后Banner,已设置Banner信息:$tmp,符合规范" >> "$csvFile"
  fi
fi

## 其他配置-3.5.30:检查日志文件权限设置
#messages=`stat -c %a /var/log/messages`
#dmesg=`stat -c %a /var/log/dmesg`
#maillog=`stat -c %a /var/log/maillog`
#secure=`stat -c %a /var/log/secure`
#wtmp=`stat -c %a /var/log/wtmp`
#cron=`stat -c %a /var/log/cron`

#if [ "$messages" -le 600 ] && [ "$secure" -le 600 ] && [ "$maillog" -le 600 ] && [ "$cron" -le 600 ] && [ "$dmesg" -le 644 ] && [ "$wtmp" -le 664 ]; then
#echo "3.5.30,$messages，$secure，$maillog，$cron，$dmesg，$wtmp,符合规范" >> "$csvFile"
#else
	#echo "3.5.30,$messages，$secure，$maillog，$cron，$dmesg，$wtmp,不符合规范" >> "$csvFile"
#fi

# 其他配置-3.5.30:检查FTP用户上传的文件所具有的权限

tmp=`netstat -lntp | grep ftp`
if [ -z "$tmp" ]; then
	echo "3.5.30,,检查FTP用户上传的文件所具有的权限,未开启服务,符合规范" >> "$csvFile"
else
  local_umask=`cat /etc/vsftpd/vsftpd.conf | grep local_umask | grep 022 | grep -v ^#`
  anon_umask=`cat /etc/vsftpd/vsftpd.conf | grep anon_umask | grep 022 | grep -v ^#`
  if [ -n "$local_umask" ] && [ -n "$anon_umask" ]; then
	echo "3.5.30,,检查FTP用户上传的文件所具有的权限,符合要求,符合规范" >> "$csvFile"
  else
	echo "3.5.30,,检查FTP用户上传的文件所具有的权限,不符合要求,不符合规范" >> "$csvFile"
  fi
fi

# 其他配置-3.5.31:检查FTP banner设置
tmp=`ps -ef | grep ftp | grep -v grep`
if [ -z "$tmp" ]; then
	echo "3.5.31,,检查FTP banner设置,未开启服务,符合规范" >> "$csvFile"
else
	echo "3.5.31,,检查FTP banner设置,已开启服务,需手工检查,需手工检查" >> "$csvFile"
fi


# 其他配置-3.5.32:检查/usr/bin/目录下可执行文件的拥有者属性

res=`find /usr/bin -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \; | grep -vE "su|passwd|sudo|crontab|ssh-agent|newgrp|chage|chsh|at|fusermount|expiry|bsd-write|gpasswd|pkexec|wall|umount|mount|chfn|screen|write|staprun"`
if [ -n "$res" ]; then
	echo "3.5.32,,检查/usr/bin/目录下可执行文件的拥有者属性,不符合要求,不符合规范" >> "$csvFile"
else
	echo "3.5.32,,检查/usr/bin/目录下可执行文件的拥有者属性,符合要求,符合规范" >> "$csvFile"
fi

# 其他配置-3.5.33:检查Telnet banner设置


#systemctl是centos7&redhat7
#tmp=`systemctl status telnet.socket  | grep active`
tmp=`service telnet.socket status | grep active`
if [ -z "$tmp" ]; then
	echo "3.5.33,,检查Telnet banner设置,未开启服务,符合规范" >> "$csvFile"
else
	echo "3.5.33,,检查Telnet banner设置,已开启服务,需手工检查,需手工检查" >> "$csvFile"
fi

# 其他配置-3.5.34:检查是否限制FTP用户登录后能访问的目录
tmp=`ps -ef | grep ftp | grep -v grep`
if [ -z "$tmp" ]; then
	echo "3.5.34,,检查是否限制FTP用户登录后能访问的目录,未开启服务,符合规范" >> "$csvFile"
else
  chroot_local_user=`cat /etc/vsftpd/vsftpd.conf | grep ^chroot_local_user=NO`
  chroot_list_enable=`cat /etc/vsftpd/vsftpd.conf | grep ^chroot_list_enable=YES`
  chroot_list_file=`cat /etc/vsftpd/vsftpd.conf | grep ^chroot_list_file=/etc/vsftpd/chroot_list`
  if [ -n "$chroot_local_user" ] && [ -n "$chroot_list_enable" ] && [ -n "$chroot_list_file" ]; then
	echo "3.5.34,,检查是否限制FTP用户登录后能访问的目录,符合要求,符合规范" >> "$csvFile"
  else
	echo "3.5.34,,检查是否限制FTP用户登录后能访问的目录,不符合要求,不符合规范" >> "$csvFile"
  fi
fi

# 其他配置-3.5.35:检查是否关闭不必要的服务和端口

# chkconfig=`chkconfig --list`
checkRes=`service --status-all | grep + | grep -vE "apparmor|apport|atd|cron|dbus|docker|iscsid|kdump-tools|kexec|kexec-load|kmod|multipath-tools|named|ntp|procps|rpcbind|rsyslog|ssh|udev|ufw|unattended-upgrades"`
if [ -n "$checkRes" ];then
	echo "3.5.35,,检查是否关闭不必要的服务和端口,开启的服务和端口,需手工检查,需手工检查">> "$csvFile"
else
	echo "3.5.35,,检查是否关闭不必要的服务和端口,未开启不必要的服务和端口,符合规范">> "$csvFile"
fi


# 其他配置-3.5.36:检查内核版本是否处于CVE-2021-43267漏洞影响版本
kernel=`uname -r | awk -F- '{ print $1 }' `
kernel1=`uname -r | awk -F- '{ print $1 }' | awk -F. '{ print $1 }'`
kernel2=`uname -r | awk -F- '{ print $1 }' | awk -F. '{ print $2 }'`
kernel3=`uname -r | awk -F- '{ print $1 }' | awk -F. '{ print $3 }'`
#5.10-rc1<Linux kernel < 5.14.16
if [ $kernel1 -eq 5 ]; then
	if [ $kernel2 -ge 10 ]&&[ $kernel2 -le 14 ]; then
		if [ $kernel3 -ge 0 ]&&[ $kernel3 -le 16 ]; then
			echo "3.5.36,,检查内核版本是否处于CVE-2021-43267漏洞影响版本,内核版本在5.10-rc1和5.14.16之间,不符合规范" >> "$csvFile"
		else
			echo "3.5.36,,检查内核版本是否处于CVE-2021-43267漏洞影响版本,内核版本不在5.10-rc1和5.14.16之间,符合规范 " >> "$csvFile"
		fi

	else
		echo "3.5.36,,检查内核版本是否处于CVE-2021-43267漏洞影响版本,内核版本不在5.10.X-rc1和5.14.X之间,符合规范" >> "$csvFile"
	fi

else
	echo "3.5.36,,检查内核版本是否处于CVE-2021-43267漏洞影响版本,内核版本不是5.X.X,符合规范" >> "$csvFile"
fi


da=`date`
echo "扫描时间：$da"
echo "已保存 ==> $csvFile"

iconv -f UTF-8 -t GBK $csvFile -o $csvFile

