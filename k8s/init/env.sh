#!/bin/bash
# set -x
# exec 1>>/tmp/env.log 2>>/tmp/env.log
function Change_Limit(){
    if ! grep pam_limits.so /etc/pam.d/login > /dev/null;then
        echo "session required /lib64/security/pam_limits.so" >> /etc/pam.d/login
        echo "* soft nofile 65536" >> /etc/security/limits.conf #配置所有用户的 当前生效最大文件打开数。
        echo "* hard nofile 65536" >> /etc/security/limits.conf #配置所有用户的 系统最大文件打开数
        echo "* soft nproc 10000" >> /etc/security/limits.conf #配置所有用户的 当前最大进程数
        echo "* hard nproc 16384" >> /etc/security/limits.conf #配置所有用户的 系统最大进程数
    fi
}

# 升级系统到最新版本软件
yum update -y
# 升级内核版本为4.4
cat > /etc/yum.repos.d/elrepo.repo <<-EOF
[elrepo]
name=ELRepo.org Community Enterprise Linux Repository – el7
baseurl=https://mirrors.ustc.edu.cn/elrepo/elrepo/el7/\$basearch/
enabled=1
gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-elrepo.org
protect=0

[elrepo-archive]
name=ELRepo.org Community Enterprise Linux Kernel Repository – el7
baseurl=https://mirrors.ustc.edu.cn/elrepo/archive/kernel/el7/\$basearch/
enabled=1
gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-elrepo.org
protect=0
EOF
yum makecache
KernelUpgrade="
kernel-lt-4.4.171-1.el7.elrepo.x86_64
kernel-lt-devel-4.4.171-1.el7.elrepo.x86_64
"
yum install -y ${KernelUpgrade}
sed -i 's/GRUB_DEFAULT.*$/GRUB_DEFAULT=0/g' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg
# 配置内核参数
swapoff -a
cat > /etc/sysctl.d/k8s.conf <<-EOF
# This script is created by charles
# tcp/ip
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_retries1 = 3
net.ipv4.tcp_retries2 = 5
net.ipv4.tcp_orphan_retries = 3
net.ipv4.tcp_fin_timeout = 5
net.ipv4.tcp_max_tw_buckets = 20000
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 0
net.ipv4.tcp_max_orphans = 32768
net.ipv4.tcp_abort_on_overflow = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_stdurg = 0
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_reordering = 5
net.ipv4.tcp_retrans_collapse = 0
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_mem = 786432 1048576 1572864
net.ipv4.ip_forward = 1
net.ipv4.ip_local_port_range = 40000 65500
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0

# netfilter
net.netfilter.nf_conntrack_max = 131072
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 3600

# core
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 16384
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# kernel
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
kernel.printk_ratelimit = 30
kernel.printk_ratelimit_burst = 200
vm.swappiness=0
EOF
sysctl -p /etc/sysctl.d/k8s.conf
Change_Limit  # 修改limit连接数
sed -i '/^SELINUX/s/SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
cp -rvf /etc/fstab /etc/fstab_old
sed -i '/swap/d' /etc/fstab
setenforce 0
systemctl stop firewalld
systemctl disable firewalld
/sbin/iptables-save > /root/iptables.bak
iptables -F &&  iptables -X &&  iptables -F -t nat &&  iptables -X -t nat && iptables -P FORWARD ACCEPT
# 安装基础软件
Yum_software="
psmisc
lrzsz
vim
ntpdate
make
net-tools 
ipset 
socat 
ipvsadm 
conntrack-tools.x86_64 
iptables 
iptables-services 
wget 
nfs-utils 
conntrack-tools 
yum-utils
device-mapper-persistent-data 
lvm2 
curl 
openssl 
openssl-devel
yum-plugin-versionlock
"
yum remove docker docker-common docker-selinux docker-engine -y
yum install -y ${Yum_software}
/usr/sbin/ntpdate cn.ntp.org.cn
/usr/sbin/clock -w
echo "10 * * * * /usr/sbin/ntpdate cn.ntp.org.cn &>/dev/null;/usr/sbin/clock -w" >> /var/spool/cron/root