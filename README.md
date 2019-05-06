[TOC]

# k8s部署脚本

支持单master 多master ，受到别人项目启发，使用nginx tcp负载均衡方式来支持apiserver的负载均衡,具体架构如下图：
![](https://imgs.matchvs.com/static/k8s/k8s11.png)

**已知问题： master 节点为偶数时，当机器宕机超过master节点半数后，会导致etcd 无法使用，整个集群全部丢失。请在部署时使用3台或者3台以上奇数的master节点来部署。**

## 环境要求
    python: 2.7 
    os: centos 7

##  组件说明：
#### ingress
    ingress-nginx (daemonset + hostPort)
#### dns：
    coredns
#### 网络插件：
    calico 、 flannel
#### 监控：
    heapster、prometheus、metric-server
#### serverless：
    kubeless
#### 显示页面：
    kubernetes-dashboard
#### 存储：
    rook-ceph  
#### 包安装管理：
    helm
#### 容器行为管理
    falco
##安装python-pip
yum -y install python-pip

## 安装python依赖
    pip install -r requirements.txt

## 修改config.toml

## 初始化服务器与安装相应的rpm包
    python manage.py Init

## 安装k8s
    python manage.py Install

## 增加节点
    在配置文件[Node] 里添加对应的ip 与 hostname
### 为添加的node初始化环境
    python manage.py ExtendEnv
### 为添加的node 安装kubeadm并加入k8s集群
    python manage.py AddNode