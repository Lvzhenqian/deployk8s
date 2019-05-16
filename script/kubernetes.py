#!/usr/bin/env python
# coding:utf-8
import os, toml, yaml, time
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
from .Base import BaseObject


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

    def __CreateNginxHAConf(self):
        self.logger.debug(u"开始生成nginx配置文件！！")
        if not os.path.exists(self.tmp):
            os.mkdir(self.tmp)
        nginxconf = os.path.join(self.tmp, "nginx.conf")
        if not os.path.exists(nginxconf):
            server = "\n".join(["server %s:6443         max_fails=3 fail_timeout=3s;" % i for i in self.Masters])
            Conf = '''user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;
include /usr/share/nginx/modules/*.conf;
worker_rlimit_nofile 65535;
events {
    use epoll;
    worker_connections 65535;
}

stream {
    upstream api-servers {
        hash $remote_addr consistent;
        %s
    }

    server {
        listen %s;
        proxy_connect_timeout 3s;
        proxy_timeout 1800s;
        proxy_pass api-servers;
    }
}''' % (server, self.LoadBalancer)
            with open(nginxconf, 'w') as f:
                f.write(Conf)
        return nginxconf

    def __MakeNginx(self, ip):
        self.logger.debug(u"%s: 安装nginx并配置tcp负载均衡！！", ip)
        confPath = self.__CreateNginxHAConf()
        self.logger.debug(confPath)
        with self.SSH(ip) as ssh:
            ssh.runner("yum install -y nginx")
            ssh.push(confPath, "/etc/nginx/nginx.conf", ip)
            ssh.runner("systemctl start nginx")
            ssh.runner("systemctl enable nginx")
            ssh.runner("systemctl status nginx")

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
                                     'service-node-port-range': self.NodePortRang
                                 },
                                 certSANs=list(certs),
                                 timeoutForControlPlane='4m0s'),
                             imageRepository='mirrorgooglecontainers',
                             useHyperKubeImage=False, clusterName='kubernetes')
        KubeProxy = dict(apiVersion='kubeproxy.config.k8s.io/v1alpha1',
                         kind='KubeProxyConfiguration',
                         mode=self.ProxyMode)
        KubeLet = dict(apiVersion='kubelet.config.k8s.io/v1beta1',
                         kind='KubeletConfiguration',
                         MaxPods=300)
        if not os.path.exists(self.tmp):
            os.mkdir(self.tmp)
        InitConfig = os.path.join(self.tmp, 'k8s.yaml')
        with open(InitConfig, mode='w') as f:
            yaml.safe_dump_all([ClusterConfig, KubeProxy,KubeLet], stream=f, encoding="utf-8", allow_unicode=True,
                               default_flow_style=False)
        return InitConfig

    def __InitCluster(self, ip):
        config = self.__CreateConfig()
        ssh = self.SSH(ip)
        ssh.push(config, '/root/k8s.yaml', ip)
        ssh.do_script("kubeadm init --config /root/k8s.yaml")
        ssh.mkdirs("/root/.kube")
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

    def MakeInitPath(self):
        self.logger.warning(u"初始化服务器，结束后会把相应的服务器重启！！")
        pool = ThreadPoolExecutor()
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
        # 配置hostname
        AllHostname = [pool.submit(self.__SetHostName, ip) for ip in self.ALL_IP]
        wait(AllHostname, timeout=60, return_when=ALL_COMPLETED)
        # 安装kubeadm
        shell = os.path.join(self.ScriptPath, "k8s/init/kubeadm.sh")
        Version = '''sed -i '1,5s#Version.*$#Version="{}"#' {}'''.format(self.Version, shell)
        DockerData = '''sed -i '1,5s#DockerData.*$#DockerData="{}"#' {}'''.format(self.DockerData, shell)
        DockerVersion = '''sed -i '1,5s#DockerVersion.*$#DockerVersion="{}"#' {}'''.format(self.DockerVersion, shell)
        KubeletData = '''sed -i '1,5s#KubeletData.*$#KubeletData="{}"#' {}'''.format(self.KubeletData, shell)
        for cmd in (Version, DockerData, DockerVersion, KubeletData):
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
        with ThreadPoolExecutor(max_workers=len(self.Masters)) as pool:
            wait([pool.submit(self.__MakeNginx, ip) for ip in self.Masters], timeout=3600, return_when=ALL_COMPLETED)

        if len(self.Masters) > 1:
            self.__MakeMultiMaster()
        else:
            ip = self.Masters[0]
            self.token, self.CertHash = self.__InitCluster(ip)

        # 复制kubconfig到root目录
        self.__Kubeconfig()
        # 回写整个配置文件
        self.cfg['Kubeconf']["Token"] = self.token
        self.cfg['Kubeconf']["CertHash"] = self.CertHash
        with open(self.ConfPath, mode="w") as fd:
            toml.dump(self.cfg, fd)

    def SchedulerToMaster(self):
        self.logger.info(u"去掉master不调度规则，减少机器使用")
        # 去掉master不调度规则
        for ip in self.Masters:
            self.__UntaintNode(ip, self.Perfix + self.Nodes[ip])

    def __CheckMasters(self):
        FailMaster = []
        with self.SSH(self.Masters[0]) as k8s:
            for ip in self.Masters[1:]:
                state,_ = k8s.runner("kubectl get nodes|awk '/%s/{print $3}'"%self.Nodes[ip])
                if state.strip("\r\n") != "master":
                    FailMaster.append(ip)
        return FailMaster

    def ReAddMaster(self):
        self.logger.info(u"检查master安装是否完整！！")
        fail = self.__CheckMasters()
        if not fail:
            return self.logger.info(u"Master安全完整，没有错误节点！！")
        self.logger.warning(u"检测到有添加master失败的节点，重新尝试添加！！")
        # reset node
        for ip in fail:
            with self.SSH(ip) as ssh:
                ssh.runner("kubeadm reset --force")
        # copy ca key
        self.__CopyCrts(self.Masters[0],fail)
        # do add again
        for ip in fail:
            self.__JoinMaster(ip)

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
                continue
        return NotKubelet

    def ExtendEnv(self):
        self.logger.warning("扩展node,配置Node环境！！，完成后会重启node")
        pool = ThreadPoolExecutor()
        ips = self.__ExtendNodeIP()
        lst = self.__NotKubeletNodes(ips)
        self.logger.debug("ips: %s -> doing: %s",ips,lst)
        # 安装服务器环境准备
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
            # 配置hostname
            AllHostname = [pool.submit(self.__SetHostName, ip) for ip in self.ALL_IP]
            wait(AllHostname, timeout=60, return_when=ALL_COMPLETED)
            shell = os.path.join(self.ScriptPath, "k8s/init/kubeadm.sh")
            nodes = [pool.submit(self.__kubeadm, ip, shell) for ip in DoIpList]
            for oj in nodes:
                self.logger.debug(oj.result())
        with ThreadPoolExecutor() as pool:
            wait([pool.submit(self.__MakeNginx, i) for i in DoIpList], timeout=3600, return_when=ALL_COMPLETED)
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

    def _flannel(self, kubectl):
        self.logger.info(u"开始安装flannel到k8s里")
        os.chdir(self.ScriptPath)
        PODip = '''sed -i 's#PODADDRESS#%s#' ./k8s/flannel/kube-flannel.yml''' % self.PodCidr
        for cmd in (PODip):
            self.subPopen(cmd)
        ssh = self.SSH(kubectl)
        ssh.mkdirs('/tmp/flannel')
        self._SSL_sender("./k8s/flannel", '/tmp/flannel', kubectl)
        ssh.runner('kubectl create -f /tmp/flannel')
        self.logger.info("flannel install successfully!")

    def _dashboard(self, kubectl):
        self.logger.info(u"开始安装kube-dashboard")
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

    def _MetricServer(self, ip):
        self.logger.info(u"开始安装metric-server到k8s里")
        with self.SSH(ip) as ssh:
            ssh.mkdirs('/tmp/metric-server')
            self._SSL_sender("./k8s/metric-server", '/tmp/metric-server', ip)
            ssh.runner('kubectl create -f /tmp/metric-server')

    def _Prometheus(self, ip):
        self.logger.info(u"开始安装prometheus到k8s里")
        if not os.path.exists(self.tmp):
            os.mkdir(self.tmp)
        ValueFile = {
            "alertmanager": {
                'alertmanagerSpec': {'image': dict(repository="registry.matchvs.com/k8s/alertmanager", tag="v0.16.1")}
            },
            "grafana": {'adminPassword': self.GrafanaPassword,
                        "image": dict(repository="registry.matchvs.com/k8s/grafana", tag="6.0.2")},
            "prometheusOperator": {'cleanupCustomResource': True,
                                   'image': dict(
                                       repository="registry.matchvs.com/k8s/prometheus-operator", tag="v0.29.0"),
                                   'configmapReloadImage': dict(
                                       repository="registry.matchvs.com/k8s/configmap-reload", tag="v0.0.1"),
                                   'prometheusConfigReloaderImage': dict(
                                       repository="registry.matchvs.com/k8s/prometheus-config-reloader", tag="v0.29.0"),
                                   "hyperkubeImage": dict(
                                       repository="registry.matchvs.com/k8s/hyperkube", tag="v1.12.1")
                                   },
            "prometheus": dict(
                prometheusSpec=dict(image=dict(repository="registry.matchvs.com/k8s/prometheus", tag="v2.7.1"))),
            "kube-state-metrics": {'image': dict(repository="registry.matchvs.com/k8s/kube-state-metrics", tag="v1.5.0")
                                   },
            "prometheus-node-exporter": {"image": dict(repository="registry.matchvs.com/k8s/node-exporter",
                                                       tag="v0.17.0")}
        }
        pro = os.path.join(self.tmp, 'prometheus.yaml')
        with open(pro, mode='w') as f:
            yaml.safe_dump(ValueFile, stream=f, encoding="utf-8", allow_unicode=True,
                           default_flow_style=False)
        with self.SSH(ip) as ssh:
            ssh.push(pro, "/tmp/prometheus.yaml", ip)
            ssh.do_script("/usr/bin/helm repo update")
            ssh.do_script(
                "/usr/bin/helm install -f /tmp/prometheus.yaml --namespace prometheus --wait --timeout 600"
                " --name prometheus stable/prometheus-operator --version 5.0.10")
        return self.logger.info("prometheus install successfully!")

    def _rook(self, kubectl):
        self.logger.info("开始安装rook程序")
        ssh = self.SSH(kubectl)
        ssh.mkdirs('/tmp/ceph')
        self._SSL_sender("./k8s/ceph", '/tmp/ceph', kubectl)
        ssh.do_script("cd /tmp/ceph && /bin/bash /tmp/ceph/install.sh")
        self.logger.info("rook install successfully!")

    def _kubeless(self, ip):
        self.logger.info("开始安装kubeless程序")
        with self.SSH(ip) as ssh:
            ssh.mkdirs('/tmp/kubeless')
            self._SSL_sender("./k8s/kubeless", '/tmp/kubeless', ip)
            ssh.runner("kubectl create ns kubeless")
            ssh.runner("chmod a+x /tmp/kubeless/kubeless")
            ssh.runner("mv /tmp/kubeless/kubeless /bin/kubeless")
            ssh.runner('kubectl create -f /tmp/kubeless')

    def _falco(self, ip):
        self.logger.info("开始安装falco程序")
        with self.SSH(ip) as ssh:
            ssh.mkdirs('/tmp/falco')
            self._SSL_sender("./k8s/falco", '/tmp/falco', ip)
            ssh.runner('kubectl create -f /tmp/falco/falco-account.yaml')
            ssh.runner('kubectl create -f /tmp/falco/falco-service.yaml')
            ssh.runner('kubectl create configmap falco-config --from-file=/tmp/falco/conf')
            ssh.runner('kubectl create -f /tmp/falco/falco-daemonset-configmap.yaml')

    def _helm(self, kubectl):
        self.logger.info("开始安装helm程序")
        ssh = self.SSH(kubectl)
        ssh.push("./k8s/helm/helm", "/usr/bin/helm", kubectl)
        ssh.runner(r"chmod a+x /usr/bin/helm")
        version, _ = ssh.runner(r'/usr/bin/helm version|head -1|egrep -o "v[0-9]+\.[0-9]+\.[0-9]"')
        self.logger.debug(version)
        ssh.do_script("helm init --upgrade -i registry.cn-hangzhou.aliyuncs.com/google_containers/tiller:%s "
                      "--stable-repo-url http://mirror.azure.cn/kubernetes/charts/" % version.split("\r\n")[0])
        ssh.runner("kubectl create serviceaccount --namespace kube-system tiller")
        ssh.runner(
            "kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller")
        ssh.runner(
            '''kubectl patch deploy tiller-deploy -p '{"spec":{"template":{"spec":{"serviceAccount":"tiller"}}}}' -n kube-system''')
        ssh.runner("/usr/bin/helm repo add bitnami https://charts.bitnami.com/bitnami")
        ssh.runner("/usr/bin/helm repo update")
        self.CheckRuning("tiller", kubectl)
        self.logger.info("helm install successfully!")

    def __IngressNginx(self, ip, other=None):
        self.logger.info("开始安装Ingress！！")
        NginxValue = dict(
            daemonset=dict(useHostPort=True, hostPorts=dict(http=80, https=443)),
            extraEnvs=[dict(name="TZ", value="Asia/Shanghai")],
            kind="DaemonSet",
            updateStrategy=dict(rollingUpdate=dict(maxUnavailable=1), type="RollingUpdate"),
            securityContext=dict(fsGroup=1000, runAsUser=1000),
            stats=dict(enable=True),
            metrics=dict(enable=True)
        )
        if other and isinstance(other, dict):
            NginxValue.update(other)

        filepath = os.path.join(self.tmp, "nginxvalue.yaml")
        with open(filepath, mode='w') as f:
            yaml.safe_dump(NginxValue, stream=f, encoding="utf-8", allow_unicode=True,
                           default_flow_style=False)
        with self.SSH(ip) as ssh:
            ssh.push(filepath, '/root/nginxvalue.yaml', ip)
            ssh.runner(
                "helm install -f /root/nginxvalue.yaml --name nginx --namespace nginx bitnami/nginx-ingress-controller")
            self.logger.info(u"重启kube-proxy，防止容器卡死")
            ssh.do_script('''for i in $(kubectl -n kube-system get pods  -l k8s-app=kube-proxy|awk '/kube-proxy/{print $1}');do kubectl -n kube-system delete pod $i;done''')
        self.logger.info(u"Ingress安装成功")

    def NetworkAddons(self, ip):
        switch = {
            "calico": self._calico,
            "flannel": self._flannel
        }
        return switch[self.Network](ip)

    def Addons(self):
        ip = self.Masters[0]
        self.NetworkAddons(ip)
        self._dashboard(ip)
        self._helm(ip)
        self._MetricServer(ip)
        self._Prometheus(ip)
        self._rook(ip)
        self._kubeless(ip)
        self._falco(ip)
        self.__IngressNginx(ip)

    def __Reset(self, ip):
        with self.SSH(ip) as ssh:
            ssh.do_script("kubeadm reset --force")
            ssh.runner("systemctl stop docker")

    def Remove(self):
        with ThreadPoolExecutor(max_workers=10) as th:
            wait([th.submit(self.__Reset, ip) for ip in self.ALL_IP], timeout=3600, return_when=ALL_COMPLETED)
