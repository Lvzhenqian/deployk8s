#!/bin/bash
IPAddress="$1"
Version="1.13.2"
DockerVersion="3:docker-ce-18.09.2-3.el7.x86_64"
DockerData="/data/docker"
KubeletData="/data/kubelet"

echo "准备安装docker"
if ping -c 1 www.google.com &> /dev/null;then
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
else
    yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
fi
yum makecache fast
yum -y install ${DockerVersion}
yum versionlock docker-ce
systemctl start docker
tee /etc/docker/daemon.json <<-'EOF'
{
    "log-driver": "json-file",
    "log-opts": {
    "max-size": "100m",
    "max-file": "3"
    },
    "exec-opts": ["native.cgroupdriver=systemd"],
    "max-concurrent-downloads": 10,
    "max-concurrent-uploads": 10,
    "registry-mirrors": ["https://sgn4c8bb.mirror.aliyuncs.com"],
    "storage-driver": "overlay2",
    "storage-opts": [
    "overlay2.override_kernel_check=true"
    ]
}
EOF
sed -i 's@^ExecStart.*$@ExecStart=/usr/bin/dockerd --data-root '${DockerData}' -H fd:// -H tcp://'${IPAddress}':6666 --log-level=info@' /lib/systemd/system/docker.service
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
sed -i -r 's#KUBELET_EXTRA_ARGS=.*$#KUBELET_EXTRA_ARGS="--root-dir='${KubeletData}' --cgroup-driver=systemd"#g' /etc/sysconfig/kubelet
systemctl daemon-reload
systemctl restart kubelet
systemctl enable kubelet