[TOC]

# k8s部署脚本
    支持单master 多master 以及 keepalived+haproxy 多master等。
## 环境要求
    python: 2.7  
    os: centos 7  

##  组件说明：
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