#!/usr/bin/env python
# coding:utf-8
from .Loger import getLogger, DEBUG, console, file_hand
from .SSHClient import SSH
from subprocess import Popen, PIPE
from tempfile import mktemp
from functools import partial
from random import random
import os, sys, toml, time,hashlib

class DockerIsExist(Exception):
    pass

class MasterIsExist(Exception):
    pass

class NodeIsExist(Exception):
    pass

class BaseObject(object):
    tmp = mktemp()
    KUBE_BINS = "/usr/local/zhangwan/k8s/bin"
    registry = "registry.matchvs.com"
    KUBE_SSL = "/etc/kubernetes/ssl"
    SERVICE_CIDR = "10.254.0.0/16"
    CLUSTER_CIDR = "172.30.0.0/16"
    secure_port = 6443
    insecure_port = 8080
    CLUSTER_DNS_SVC_IP = "10.254.0.2"
    NODE_PORT_RANGE = "60-52766"
    CLUSTER_KUBERNETES_SVC_IP = "10.254.0.1"
    DOCKER_DATA = '/data/docker'
    KUBELET_DATA = "/data/kubelet"
    KUBE_PROXY = "/data/kube-proxy"
    ETCD_DATA = "/data/etcd"
    BackUpDir = '/data/MatchvsBackup'

    def __init__(self, conf):
        self.etcd_node = []
        self.etcd_endpoint = []
        self.logger = getLogger(name='kubernetes')
        self.logger.setLevel(DEBUG)
        self.logger.propagate = False
        self.logger.addHandler(console)
        self.logger.addHandler(file_hand)
        self.ScriptPath = os.getcwd()
        with open(conf) as cf:
            self.cfg = toml.load(cf)
        self.SSH = partial(SSH, port=int(self.cfg['SSH_SETTING']['SSH_PORT']),
                           user=self.cfg['SSH_SETTING']['SSH_USER'],
                           passwd=self.cfg['SSH_SETTING']['SSH_PASSWORD'])
        self.ALL_IP = set(self.cfg['NODES']['IPS'].keys())
        self.ALL_IP.update(self.cfg['ETCD']['IPS'])
        self.logger.debug(self.ALL_IP)
        if not self.cfg['BOOTSTRAP_TOKEN'] or self.cfg['BOOTSTRAP_TOKEN'] == '73f97aad8cc1023ecfa37e4adf919738':
            self.cfg['BOOTSTRAP_TOKEN'] = hashlib.md5(str(random())).hexdigest()
        self.logger.info("BOOTSTRAP_TOKEN: {}".format(self.cfg['BOOTSTRAP_TOKEN']))

    def _Systemd_Check(self, ip, name):
        ssh = self.SSH(ip)
        for _ in xrange(120):
            msg, stat = ssh.runner('systemctl is-active {name}'.format(name=name))
            if msg.strip() == 'active':
                self.logger.info("{ip} {name} install successfully!".format(ip=ip, name=name))
                return self.logger.debug(ssh.runner('systemctl status {name}'.format(name=name)))
            self.logger.warning("{ip} {name} status:{msg}".format(ip=ip, name=name, msg=msg))
            time.sleep(30)
            self.logger.debug(ssh.runner('systemctl status {name}'.format(name=name)))
        else:
            self.logger.error("{ip} {name} start fail!!".format(ip=ip, name=name))
            sys.exit(-1)

    def checker(self,ip):
        ssh = self.SSH(ip)
        etcd, stat = ssh.runner("systemctl is-active etcd")
        kubelet, stat = ssh.runner("systemctl is-active kubelet")
        docker, stat = ssh.runner("systemctl is-active docker")
        self.logger.debug(etcd.strip())
        self.logger.debug(kubelet.strip())
        self.logger.debug(docker.strip())
        if etcd.strip() == 'active':
            raise MasterIsExist(u"%s: etcd 服务正在运行！！" % ip)
        if kubelet.strip() == 'active':
            raise NodeIsExist(u"%s: kubelet 程序已经在运行，请检查节点！！" % ip)
        if docker.strip() == 'active':
            raise DockerIsExist(u"%s: docker 程序已经在运行，请检查节点！！" % ip)

    def InitCheck(self):
        self.logger.info(u"安装前检查是否已经存在k8s环境")
        for ip in self.ALL_IP:
            self.checker(ip)

    def _SSL_sender(self, path, remotepath, ip):
        ssh = self.SSH(ip)
        for files in os.listdir(path):
            src = os.path.join(path, files)
            dst = os.path.join(remotepath, files)
            if files.endswith('.service'):
                dst = os.path.join('/etc/systemd/system', files)
            ssh.push(src, dst, ip)

    def CheckingNode(self, kubectl):
        self.logger.info(u"检查并等待node 加入k8s里")
        ssh = self.SSH(kubectl)
        stats = {}
        while True:
            msg, stat = ssh.runner('{KUBE_BINS}/kubectl get nodes|grep -v "^NAME"'.format(
                KUBE_BINS=BaseObject.KUBE_BINS))
            for line in msg.splitlines():
                try:
                    name, stat, roles, age, version = line.split()
                except ValueError, e:
                    self.logger.error(line)
                    self.logger.error(e)
                if stat != 'Ready':
                    self.logger.warning("{name}: {stat}".format(name=name, stat=stat))
                else:
                    stats[name] = stat
            if len(stats.keys()) == len(self.cfg['NODES']['IPS'].keys()):
                for name, stat in stats.items():
                    self.logger.info("{name}: {stat}".format(name=name, stat=stat))
                return True
            self.logger.debug(stats)
            time.sleep(30)

    def CheckRuning(self, name, ip):
        self.logger.info(u"{name} 正在启动中！".format(name=name))
        ssh = self.SSH(ip)
        while True:
            msg, stat = ssh.runner('{KUBE_BINS}/kubectl get pods --all-namespaces|grep "{name}"'.format(
                KUBE_BINS=BaseObject.KUBE_BINS, name=name))
            self.logger.debug(msg)
            if msg:
                for line in msg.split('\r\n'):
                    if line:
                        self.logger.debug(line)
                        try:
                            namespaces, podname, ready, status, restarts, age = line.split()
                        except ValueError, e:
                            self.logger.error(line)
                            self.logger.error(e)
                            break
                        if status != 'Running':
                            self.logger.warning(' '.join((podname, ready, status)))
                            break
                        else:
                            self.logger.info(' '.join((podname, ready, status)))
                else:
                    break
            time.sleep(20)
        return self.logger.info("{name} install successfully!".format(name=name))

    def subPopen(self, cmd):
        self.logger.debug(cmd)
        o = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
        return self.logger.debug({
            'stdout': o.stdout.read(),
            'stderr': o.stderr.read()
        })

    def testcmd(self,ip,cmd):
        print(cmd)
        msg = self.SSH(ip).runner(cmd)
        print(msg)

