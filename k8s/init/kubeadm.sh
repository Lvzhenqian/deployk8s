#!/bin/bash
Version="1.13.2"
DockerVersion="3:docker-ce-18.09.2-3.el7.x86_64"
DockerData="/data/docker"
KubeletData="/data/kubelet"
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
echo "安装软件： ${Yum_software}, 状态：$?"
echo "准备安装docker"
if ping -c 1 www.google.com &> /dev/null;then
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    yum install -y epel-release
else
    yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
    wget -O /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo
fi
yum makecache fast
yum -y install ${DockerVersion}
yum versionlock docker-ce
systemctl start docker
tee /etc/docker/daemon.json <<-'EOF'
{
  "registry-mirrors": ["https://b4n0ghyv.mirror.aliyuncs.com"],
  "max-concurrent-downloads": 10,
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m" },
  "storage-driver": "overlay2",
  "storage-opts": ["overlay2.override_kernel_check=true"]
}
EOF
sed -i 's@^ExecStart.*$@ExecStart=/usr/bin/dockerd --data-root '${DockerData}' --log-level=info@' /lib/systemd/system/docker.service
systemctl daemon-reload
systemctl restart docker
cat > /etc/sysctl.d/docker.conf <<-EOF
# bridge
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
sysctl --system
systemctl start docker
systemctl enable docker

echo "准备安装kubeadm"
cat > /etc/yum.repos.d/kubenetes.repo <<-EOF
[kubenetes]
name=Kubenetes Repo
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64/
gpgcheck=0
enabled=1
EOF
yum makecache
package=$(yum search --showduplicates kubeadm kubelet kubectl|awk '/'${Version}'/{print $1}')
yum install -y ${package}
mkdir -p ${KubeletData}
sed -i -r 's#KUBELET_EXTRA_ARGS=.*$#KUBELET_EXTRA_ARGS="--root-dir='${KubeletData}'"#g' /etc/sysconfig/kubelet
systemctl daemon-reload
systemctl restart kubelet
systemctl enable kubelet