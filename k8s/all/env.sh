#!/bin/bash
# set -x
# exec 1>>/tmp/env.log 2>>/tmp/env.log
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
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0

# netfilter
net.netfilter.nf_conntrack_max = 65536
net.netfilter.nf_conntrack_tcp_timeout_established = 7200

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
sed -i '/^SELINUX/s/SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
cp -rvf /etc/fstab /etc/fstab_old
sed -i '/swap/d' /etc/fstab
setenforce 0
systemctl stop firewalld
systemctl disable firewalld
/sbin/iptables-save > /root/iptables.bak
iptables -F &&  iptables -X &&  iptables -F -t nat &&  iptables -X -t nat && iptables -P FORWARD ACCEPT
Yum_software="make net-tools ipset ipvsadm conntrack-tools.x86_64 iptables iptables-services wget nfs-utils conntrack-tools yum-utils device-mapper-persistent-data lvm2 curl openssl openssl-devel"
yum remove docker docker-common docker-selinux docker-engine -y
yum install -y ${Yum_software}
if ping -c 1 www.google.com &> /dev/null;then
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
else
    yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
fi
yum makecache fast
yum -y install docker-ce
systemctl start docker
tee /etc/docker/daemon.json <<-'EOF'
{
  "max-concurrent-downloads": 10,
  "log-driver": "json-file",
  "log-opts": { "max-size": "1G" }
}
EOF
systemctl daemon-reload
systemctl restart docker
exit 0