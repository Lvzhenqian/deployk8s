# k8s部署脚本

## 环境要求
python: 2.7
os: centos 7

##  组件说明：
calico  3.4
rook-ceph 0.9.2
dashboard v1.8.3
heapster v1.5.4
helm v2.12.1

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