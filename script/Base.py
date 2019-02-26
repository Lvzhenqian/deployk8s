#!/usr/bin/env python
# coding:utf-8
from .Loger import getLogger, DEBUG, console, file_hand
from .SSHClient import SSH
from subprocess import Popen, PIPE
from tempfile import mktemp
from functools import partial
import os, sys, time,socket
from datetime import datetime
from .Config import Config

class DockerIsExist(Exception):
    pass

class MasterIsExist(Exception):
    pass

class NodeIsExist(Exception):
    pass

class BaseObject(Config):
    tmp = mktemp()

    def __init__(self, conf):
        super(BaseObject,self).__init__(conf)
        self.before = datetime.now()
        self.logger = getLogger(name='kubernetes')
        self.logger.setLevel(DEBUG)
        self.logger.propagate = False
        self.logger.addHandler(console)
        self.logger.addHandler(file_hand)
        self.ScriptPath = os.getcwd()
        if self.SshPkey:
            keypass = self.SshPkeypass if self.SshPkeypass else None
            self.SSH = partial(SSH, port=int(self.SshPort),user=self.SshUsername,pKey=self.SshPkey,keypass=keypass)
        else:
            self.SSH = partial(SSH, port=int(self.SshPort),user=self.SshUsername,passwd=self.SshPassword)
        self.ALL_IP = set(self.Nodes.keys())
        self.ALL_IP.update(self.Masters)
        self.logger.debug(self.ALL_IP)


    def _Systemd_Check(self, ip, name):
        ssh = self.SSH(ip)
        for _ in range(120):
            msg, stat = ssh.runner('systemctl is-active {}'.format(name))
            if msg.strip() == 'active':
                self.logger.info("%s %s install successfully!",ip,name)
                return self.logger.debug(ssh.runner('systemctl status %s',name))
            self.logger.warning("%s %s status:%s",ip,name,msg)
            time.sleep(30)
            self.logger.debug(ssh.runner('systemctl status %s',name))
        else:
            self.logger.error("%s %s start fail!!",ip,name)
            sys.exit(-1)

    def checker(self,ip):
        ssh = self.SSH(ip)
        kubelet, stat = ssh.runner("systemctl is-active kubelet")
        docker, stat = ssh.runner("systemctl is-active docker")
        self.logger.debug(kubelet.strip())
        self.logger.debug(docker.strip())
        if kubelet.strip() == 'active':
            raise NodeIsExist(u"{}: kubelet 程序已经在运行，请检查节点！！".format(ip))
        if docker.strip() == 'active':
            raise DockerIsExist(u"{}: docker 程序已经在运行，请检查节点！！".format(ip))

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

    def CheckRuning(self, name, ip):
        self.logger.info(u"%s 正在启动中！",name)
        ssh = self.SSH(ip)
        while True:
            msg, stat = ssh.runner('kubectl get pods --all-namespaces|grep "{}"'.format(name))
            self.logger.debug(msg)
            if msg:
                for line in msg.split('\r\n'):
                    if line:
                        self.logger.debug(line)
                        try:
                            namespaces, podname, ready, status, restarts, age = line.split()
                        except ValueError as e:
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
        return self.logger.info("%s install successfully!",name)

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

    def testshell(self,ip,shell):
        print(shell)
        ssh = self.SSH(ip)
        lst = ssh.do_script(shell)
        print(lst)

    def TestSshPort(self,ip,port):
        while True:
            try:
                so = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                so.settimeout(30)
                so.connect((ip,int(port)))
                respon = so.recv(1024)
                if 'SSH' in respon:
                    self.logger.debug(respon)
                    self.logger.debug("%s: %s",ip,"successfully!!")
                    return so.close()
            except Exception , e:
                self.logger.error("%s: %s",ip,e)