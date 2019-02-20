#!/usr/bin/env python
# coding:utf-8
import os, toml, yaml, time
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
from .Base import BaseObject
from copy import copy


class kubernetes(BaseObject):

    def Env(self, ip):
        ssh = self.SSH(ip)
        ssh.push(os.path.join(self.ScriptPath, "k8s/init/env.sh"), '/tmp/env.sh', ip)
        ssh.do_script('/bin/bash /tmp/env.sh')
        return "%s done" % ip

    def __RestartServer(self, ip):
        self.logger.info(u"%s 服务器即将重启!!", ip)
        with self.SSH(ip) as ssh:
            return ssh.runner("reboot")

    def __kubeadm(self, ip, shell):
        ssh = self.SSH(ip)
        ssh.push(shell, '/tmp/kubeadm.sh', ip)
        ssh.mkdirs(self.DockerData)
        ssh.do_script('/bin/bash /tmp/kubeadm.sh')
        return "%s done" % ip

    def __SetHostName(self, ip):
        self.logger.info(u"%s 即将配置并修改hosts文件，旧hosts保存为 /etc/hosts_old !!" % ip)
        hostname = self.Perfix + self.Nodes[ip]
        hosts = '\n'.join([" ".join((node, self.Perfix + name)) for node, name in self.Nodes.items()])
        header = '''127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6\n'''
        setname = "hostnamectl set-hostname %s" % hostname
        BackupHosts = "/bin/cp -rf /etc/hosts /etc/hosts_old"
        InsertHosts = 'echo "{}" > /etc/hosts'.format(header + hosts)
        with self.SSH(ip) as ssh:
            for cmd in (setname, BackupHosts, InsertHosts):
                ssh.runner(cmd)

    def __CreateConfig(self):
        name, _ = self.LoadBalancer.split(':')
        certs = set(self.Masters)
        certs.add(name)
        ClusterConfig = dict(apiVersion='kubeadm.k8s.io/v1beta1', kind='ClusterConfiguration',
                             etcd=dict(local=dict(imageRepository='mirrorgooglecontainers', imageTag='3.2.24',
                                                  dataDir='/data/etcd')),
                             networking=dict(serviceSubnet=self.ServiceCidr, podSubnet=self.PodCidr),
                             dns=dict(type='CoreDNS', imageRepository='coredns'), kubernetesVersion=self.Version,
                             controlPlaneEndpoint=self.LoadBalancer,
                             apiServer=dict(
                                 extraArgs={
                                     'authorization-mode': 'Node,RBAC',
                                     'insecure-port': "%s" % self.InsecurePort,
                                     'service-node-port-range': self.NodePortRang
                                 },
                                 certSANs=list(certs),
                                 timeoutForControlPlane='4m0s'),
                             imageRepository='mirrorgooglecontainers',
                             useHyperKubeImage=False, clusterName='kubernetes')
        KubeProxy = dict(apiVersion='kubeproxy.config.k8s.io/v1alpha1',
                         kind='KubeProxyConfiguration',
                         mode=self.ProxyMode)
        os.mkdir(self.tmp)
        InitConfig = os.path.join(self.tmp, 'k8s.yaml')
        with open(InitConfig, mode='w') as f:
            yaml.safe_dump_all([ClusterConfig, KubeProxy], stream=f, encoding="utf-8", allow_unicode=True,
                               default_flow_style=False)
        return InitConfig

    def __InitCluster(self, ip):
        config = self.__CreateConfig()
        ssh = self.SSH(ip)
        ssh.push(config, '/root/k8s.yaml', ip)
        ssh.do_script("kubeadm init --config /root/k8s.yaml")
        ssh.runner("/bin/cp -rf /etc/kubernetes/admin.conf /root/.kube/config")
        ret, _ = ssh.runner("kubeadm token create --ttl 0 --print-join-command")
        # self.logger.debug(ret)
        _, _, _, _, token, _, Certhash = ret.split()
        return token, Certhash.strip("\r\n")

    def __Kubeconfig(self):
        self.logger.info(u"复制kubeconfig 到$HOME/.kube/config")
        for ip in self.Masters:
            with self.SSH(ip) as ssh:
                ssh.mkdirs("/root/.kube")
                ssh.runner("/bin/cp -rf /etc/kubernetes/admin.conf /root/.kube/config")
                ssh.runner("chown root.root $HOME/.kube/config")

    def __CopyCrts(self, master, IpList):

        with self.SSH(master) as mt:
            CaCrt, _ = mt.runner("cat /etc/kubernetes/pki/ca.crt")
            CaKey, _ = mt.runner("cat /etc/kubernetes/pki/ca.key")
            SaKey, _ = mt.runner("cat /etc/kubernetes/pki/sa.key")
            SaPub, _ = mt.runner("cat /etc/kubernetes/pki/sa.pub")
            FrontCrt, _ = mt.runner("cat /etc/kubernetes/pki/front-proxy-ca.crt")
            FrontKey, _ = mt.runner("cat /etc/kubernetes/pki/front-proxy-ca.key")
            EtcdCrt, _ = mt.runner("cat /etc/kubernetes/pki/etcd/ca.crt")
            EtcdKey, _ = mt.runner("cat /etc/kubernetes/pki/etcd/ca.key")
            admin, _ = mt.runner("cat /etc/kubernetes/admin.conf")

        for ip in IpList:
            with self.SSH(ip) as ssh:
                ssh.mkdirs("/etc/kubernetes/pki/etcd")
                ssh.runner('''echo "%s" > /etc/kubernetes/pki/ca.crt''' % CaCrt)
                ssh.runner('''echo "%s" > /etc/kubernetes/pki/ca.key''' % CaKey)
                ssh.runner('''echo "%s" > /etc/kubernetes/pki/sa.key''' % SaKey)
                ssh.runner('''echo "%s" > /etc/kubernetes/pki/sa.pub''' % SaPub)
                ssh.runner('''echo "%s" > /etc/kubernetes/pki/front-proxy-ca.crt''' % FrontCrt)
                ssh.runner('''echo "%s" > /etc/kubernetes/pki/front-proxy-ca.key''' % FrontKey)
                ssh.runner('''echo "%s" > /etc/kubernetes/pki/etcd/ca.crt''' % EtcdCrt)
                ssh.runner('''echo "%s" > /etc/kubernetes/pki/etcd/ca.key''' % EtcdKey)
                ssh.runner('''echo "%s" > /etc/kubernetes/admin.conf''' % admin)

    def __UntaintNode(self, ip, nodename):
        with self.SSH(ip) as ssh:
            self.logger.debug("taint %s" % nodename)
            return ssh.runner("kubectl taint nodes {} node-role.kubernetes.io/master:NoSchedule-".format(nodename))

    def __JoinMaster(self, ip):
        with self.SSH(ip) as ssh:
            return ssh.do_script(
                "kubeadm join {} --token {} --discovery-token-ca-cert-hash {} --experimental-control-plane".format(
                    self.LoadBalancer, self.token, self.CertHash
                )
            )

    def __JoinNode(self, ip):
        with self.SSH(ip) as ssh:
            return ssh.do_script(
                "kubeadm join {} --token {} --discovery-token-ca-cert-hash {}".format(
                    self.LoadBalancer, self.token, self.CertHash
                )
            )

    def __HaProxy(self, ip):
        self.logger.debug(u"%s: 现在安装haproxy" % ip)
        with self.SSH(ip) as ssh:
            ssh.do_script("yum install -y haproxy keepalived")
        https = [' '.join(["server", "kubernetes-https-%s" % ids, "%s:6443" % i, "check\n"]) for ids, i in
                 enumerate(self.Masters)]
        self.logger.debug(https)
        http = [' '.join(["server", "kubernetes-http-%s" % ids2, "{}:{}".format(i2, self.InsecurePort), "check\n"]) for
                ids2, i2
                in enumerate(self.Masters)]
        self.logger.debug(http)
        haproxy = u'''global
    daemon
    nbproc    4
    user      haproxy
    group     haproxy
    maxconn   50000
    pidfile   /var/run/haproxy.pid
    log       127.0.0.1   local0
    chroot    /var/lib/haproxy

defaults
    log       global
    log       127.0.0.1   local0
    maxconn   50000
    retries   3
    balance   roundrobin
    option    httplog
    option    dontlognull
    option    httpclose
    option    abortonclose
    timeout   http-request 10s
    timeout   connect 10s
    timeout   server 1m
    timeout   client 1m
    timeout   queue 1m
    timeout   check 5s

listen stats
  bind %s:9000
  mode http
  stats enable
  stats hide-version
  stats uri /stats
  stats refresh 30s
  stats realm Haproxy\ Statistics
  stats auth Matchvs:Matchvs-Password
  
frontend kubernetes-https
    bind 0.0.0.0:%s  #使用0.0.0.0主要是在使用svip 时能够使得vip的端口能访问
    mode tcp
    option tcplog
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    default_backend kubernetes-https
backend kubernetes-https
    mode tcp
    option tcplog
    option tcp-check
    balance roundrobin
    default-server inter 10s downinter 5s rise 2 fall 2 slowstart 60s maxconn 250 maxqueue 256 weight 100
    %s
    
frontend kubernetes-http
    bind %s
    mode tcp
    option tcplog
    default_backend kubernetes-http
backend kubernetes-http
    mode tcp
    option tcplog
    option tcp-check
    balance roundrobin
    default-server inter 10s downinter 5s rise 2 fall 2 slowstart 60s maxconn 250 maxqueue 256 weight 100
    %s      
''' % (ip, self.LoadBalancer.split(":")[-1], '    '.join(https), "%s:680" % ip, '    '.join(http))
        with self.SSH(ip) as ssh:
            ssh.runner('''echo "%s" > /etc/haproxy/haproxy.cfg''' % haproxy)
            ssh.runner("systemctl start haproxy")
            ssh.runner("systemctl enable haproxy")
            ssh.runner("systemctl status haproxy")

    def __KeepAlived(self, ip, flag, pid):
        self.logger.debug(u"%s: 现在安装keepalived" % ip)
        OtherList = copy(self.Masters)
        OtherList.remove(ip)
        other = '\n'.join(OtherList)
        # self.logger.debug(OtherList)
        keepalived = u'''! Configuration File for keepalived
global_defs {
   notification_email {
   }
   router_id kubernetes-api
}

vrrp_script kubernetes {
    # 自身状态检测
    script "killall -0 haproxy"  #检查haproxy进程是否存在
    interval 3
    weight 5
}

vrrp_instance haproxy-vip {
    # 使用单播通信，默认是组播通信
    unicast_src_ip %s
    unicast_peer {
        %s
    }
    # 初始化状态
    state %s   #slave节点就修改为BACKUP
    # 虚拟ip 绑定的网卡
    interface %s
    # 此ID 要与Backup 配置一致
    virtual_router_id 51
    # 默认启动优先级，要比Backup 大点，但要控制量，保证自身状态检测生效
    priority %s    #slave 修改比这个数值要小一点
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {
        # 虚拟ip 地址
        %s
    }
    track_script {
        kubernetes
    }
}
''' % (ip, other, flag, self.InterfaceName, pid, self.Vip)
        with self.SSH(ip) as ssh:
            ssh.runner('''echo "%s" > /etc/keepalived/keepalived.conf''' % keepalived)
            ssh.runner('''echo "net.ipv4.ip_nonlocal_bind = 1" > /etc/sysctl.d/keepalive.conf''')
            ssh.runner("sysctl --system")
            ssh.runner("systemctl start keepalived")
            ssh.runner("systemctl enable keepalived")
            ssh.runner("systemctl status keepalived")

    def __MakeHA(self):
        if self.KeepAlived:
            self.logger.info(u"开始给Master服务器安装keepalived 与haproxy")
            self.logger.debug(self.Masters)
            for index, ip in enumerate(self.Masters):
                self.logger.debug(ip)
                flag = "MASTER" if index == 0 else 'BACKUP'
                pid = 100 if index == 0 else 98
                self.__HaProxy(ip)
                self.__KeepAlived(ip, flag, pid)
        return

    def MakeInitPath(self):
        self.logger.warning(u"初始化服务器，结束后会把相应的服务器重启！！")
        pool = ThreadPoolExecutor()
        # 配置hostname
        AllHostname = [pool.submit(self.__SetHostName, ip) for ip in self.ALL_IP]
        wait(AllHostname, timeout=60, return_when=ALL_COMPLETED)
        # 初始化环境
        AllEnv = [pool.submit(self.Env, ip) for ip in self.ALL_IP]
        wait(AllEnv, timeout=3600, return_when=ALL_COMPLETED)
        # 重启机器
        GetDoneIP = sorted([lt.result().split()[0] for lt in AllEnv], reverse=True)
        self.logger.debug(GetDoneIP)
        for ip in GetDoneIP:
            self.__RestartServer(ip)
            time.sleep(1)

    def MakeAll(self):
        pool = ThreadPoolExecutor()
        # 测试可连接性！！
        self.logger.info(u"测试集群机器是否能连接上！！")
        TestPort = [pool.submit(self.TestSshPort, ip, self.SshPort) for ip in self.ALL_IP]
        wait(TestPort, timeout=300, return_when=ALL_COMPLETED)
        self.logger.debug(TestPort)
        # 安装kubeadm
        shell = os.path.join(self.ScriptPath, "k8s/init/kubeadm.sh")
        Version = '''sed -i '1,5s#Version.*$#Version="{}"#' {}'''.format(self.Version, shell)
        DockerData = '''sed -i '1,5s#DockerData.*$#DockerData="{}"#' {}'''.format(self.DockerData, shell)
        DockerVersion = '''sed -i '1,5s#DockerVersion.*$#DockerVersion="{}"#' {}'''.format(self.DockerVersion, shell)
        for cmd in (Version, DockerData, DockerVersion):
            self.subPopen(cmd)
        AllKubeadm = [pool.submit(self.__kubeadm, ip, shell) for ip in self.ALL_IP]
        wait(AllKubeadm, timeout=3600, return_when=ALL_COMPLETED)
        self.logger.debug(AllKubeadm)

    def __MakeMultiMaster(self):
        first, others = self.Masters[0], self.Masters[1:]
        self.token, self.CertHash = self.__InitCluster(first)
        self.__CopyCrts(first, others)
        with ThreadPoolExecutor() as pool:
            for ip in others:
                pool.submit(self.__JoinMaster, ip)

    def MakeMaster(self):
        self.logger.info("初始化Masters")
        if len(self.Masters) > 1:
            self.__MakeHA()
            self.__MakeMultiMaster()
        else:
            ip = self.Masters[0]
            self.token, self.CertHash = self.__InitCluster(ip)

        # 复制kubconfig到root目录
        self.__Kubeconfig()
        # 回写整个配置文件
        self.cfg['Kubeconf']["Token"] = self.token
        self.cfg['Kubeconf']["CertHash"] = self.CertHash
        with open(os.path.join(self.ScriptPath, "config.toml"), mode="w") as fd:
            toml.dump(self.cfg, fd)

    def SchedulerToMaster(self):
        self.logger.info(u"去掉master不调度规则，减少机器使用")
        # 去掉master不调度规则
        for ip in self.Masters:
            self.__UntaintNode(ip, self.Perfix + self.Nodes[ip])

    def __ExtendNodeIP(self):
        with self.SSH(self.Masters[0]) as k8s:
            k8snodes, _ = k8s.runner("kubectl get nodes|awk '/k8s/{print $1}'")
        Haveing = set([name.strip(self.Perfix) for name in k8snodes.split("\r\n") if name])
        ConfigNodes = set(self.Nodes.values())
        self.logger.debug((Haveing, ConfigNodes))
        names = ConfigNodes.symmetric_difference(Haveing)
        return [k for k, v in self.Nodes.items() for name in names if name == v and k not in self.Masters]

    def __NotKubeletNodes(self, iplist):
        NotKubelet = []
        for ip in iplist:
            try:
                self.checker(ip)
                NotKubelet.append(ip)
            except Exception as e:
                self.logger.debug("%s: %s", ip, e)
                break
        return NotKubelet

    def ExtendEnv(self):
        self.logger.warning("扩展node,配置Node环境！！，完成后会重启node")
        # 配置hostname
        pool = ThreadPoolExecutor()
        AllHostname = [pool.submit(self.__SetHostName, ip) for ip in self.ALL_IP]
        wait(AllHostname, timeout=60, return_when=ALL_COMPLETED)
        ips = self.__ExtendNodeIP()
        lst = self.__NotKubeletNodes(ips)
        AllEnv = [pool.submit(self.Env, ip) for ip in lst]
        wait(AllEnv, timeout=3600, return_when=ALL_COMPLETED)
        for ip in lst:
            self.__RestartServer(ip)

    def AddNode(self):
        DoIpList = self.__ExtendNodeIP()
        self.logger.debug(DoIpList)
        NotKubelet = self.__NotKubeletNodes(DoIpList)
        if NotKubelet:
            pool = ThreadPoolExecutor()
            self.logger.info(u"节点没有安装docker等程序，脚本开始安装docker.")
            # 测试可连接性！！
            self.logger.info(u"测试集群机器是否能连接上！！")
            TestPort = [pool.submit(self.TestSshPort, ip, self.SshPort) for ip in DoIpList]
            wait(TestPort, timeout=300, return_when=ALL_COMPLETED)
            self.logger.debug(TestPort)
            shell = os.path.join(self.ScriptPath, "k8s/init/kubeadm.sh")
            nodes = [pool.submit(self.__kubeadm, ip, shell) for ip in DoIpList]
            for oj in nodes:
                self.logger.debug(oj.result())
        self.logger.info(u"添加node节点进k8s里！！")
        with ThreadPoolExecutor() as pool:
            ret = [pool.submit(self.__JoinNode, ip) for ip in DoIpList]
        wait(ret, timeout=300, return_when=ALL_COMPLETED)
        for ojs in ret:
            self.logger.debug(ojs.result())
        self.logger.info("添加节点成功！！等待k8s初始化好节点。")

    def _calico(self, kubectl):
        os.chdir(self.ScriptPath)
        PODip = '''sed -i -r '/CALICO_IPV4POOL_CIDR/{n;s#value: ".*"$#value: "%s"#}' ./k8s/calico/calico.yaml''' % self.PodCidr
        MTU = '''sed -i 's/1440/{}/g' ./k8s/calico/calico.yaml'''.format(self.MTU)
        for cmd in (PODip, MTU):
            self.subPopen(cmd)
        ssh = self.SSH(kubectl)
        ssh.mkdirs('/tmp/calico')
        self._SSL_sender("./k8s/calico", '/tmp/calico', kubectl)
        ssh.runner('kubectl create -f /tmp/calico')
        self.logger.info("calico install successfully!")

    def _dashboard(self, kubectl):
        os.chdir(self.ScriptPath)
        tmp = '/tmp/dashboard'
        ssh = self.SSH(kubectl)
        ssh.mkdirs(tmp)
        self._SSL_sender("./k8s/dashboard", '/tmp/dashboard', kubectl)
        ssh.runner('kubectl create -f /tmp/dashboard')
        self.CheckRuning(name="dashboard", ip=kubectl)

    def _heapster(self, kubectl):
        ssh = self.SSH(kubectl)
        ssh.mkdirs('/tmp/heapster')
        self._SSL_sender("./k8s/heapster", '/tmp/heapster', kubectl)
        ssh.runner('kubectl create -f /tmp/heapster')
        self.CheckRuning(name="monitoring-influxdb", ip=kubectl)
        self.CheckRuning(name="heapster", ip=kubectl)
        self.CheckRuning(name="monitoring-grafana", ip=kubectl)

    def _rook(self, kubectl):
        self.logger.info("开始安装rook程序")
        ssh = self.SSH(kubectl)
        ssh.mkdirs('/tmp/ceph')
        self._SSL_sender("./k8s/ceph", '/tmp/ceph', kubectl)
        ssh.do_script("cd /tmp/ceph && /bin/bash /tmp/ceph/install.sh")
        self.logger.info("rook install successfully!")

    def _helm(self, kubectl):
        self.logger.info("开始安装helm程序")
        ssh = self.SSH(kubectl)
        ssh.push("./k8s/helm/helm", "/usr/bin/helm", kubectl)
        ssh.runner("chmod a+x /usr/bin/helm")
        ssh.do_script("helm init --upgrade -i registry.cn-hangzhou.aliyuncs.com/google_containers/tiller:%s "
                      "--stable-repo-url https://kubernetes.oss-cn-hangzhou.aliyuncs.com/charts" % self.HelmVersion)
        ssh.runner("kubectl create serviceaccount --namespace kube-system tiller")
        ssh.runner(
            "kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller")
        ssh.runner(
            '''kubectl patch deploy tiller-deploy -p '{"spec":{"template":{"spec":{"serviceAccount":"tiller"}}}}' -n kube-system''')
        self.logger.info("helm install successfully!")

    def Addons(self):
        ip = self.Masters[0]
        self._calico(ip)
        self._dashboard(ip)
        self._heapster(ip)
        self._rook(ip)
        self._helm(ip)

    def DropDockerService(self, ip):
        self.logger.info(u"{address}: 卸载Docker服务，并删除文件！".format(address=ip))
        ssh = self.SSH(ip)
        ssh.runner("umount -l $(mount |awk '/kubelet/{print $3}')")
        ssh.runner("umount -l $(mount |awk '/kubelet/{print $3}')")
        ssh.runner('systemctl stop docker')

    def DropNodeService(self, ip):
        self.logger.info(u"{address}: 清理Node！！".format(address=ip))
        ssh = self.SSH(ip)
        ssh.runner("systemctl stop kubelet")
        ssh.runner("rm -rf /etc/systemd/system/kube*")

    def DropRookService(self):
        self.logger.info(u"移除rook服务!!")
        ssh = self.SSH(self.Masters[0])
        ssh.runner("kubectl delete namespace rook-ceph")
        ssh.runner("kubectl delete namespace rook-ceph-system")
