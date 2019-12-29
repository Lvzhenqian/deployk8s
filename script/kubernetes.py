#!/usr/bin/env python
# coding:utf-8
import os, toml, yaml, time, docker, sys
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
from .Base import BaseObject


class kubernetes(BaseObject):

    def Env(self, ip):
        ssh = self.SSH(ip)
        ssh.push(os.path.join(self.ScriptPath, "k8s/init/env.sh"), '/tmp/env.sh', ip)
        ssh.do_script('/bin/bash /tmp/env.sh %s'%self.Masters[0])
        return "%s done" % ip

    def __RestartServer(self, ip):
        self.logger.info(u"%s 服务器即将重启!!", ip)
        with self.SSH(ip) as ssh:
            return ssh.runner("reboot")

    def __kubeadm(self, ip, shell):
        ssh = self.SSH(ip)
        ssh.push(shell, '/tmp/kubeadm.sh', ip)
        ssh.mkdirs(self.DockerData)
        ssh.do_script('/bin/bash /tmp/kubeadm.sh %s'%ip)
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

    def __MakeProxyFromDockerSdk(self, ip):
        self.logger.info(u"%s 启动apiserver 代理程序端口！！"%ip)
        # client = docker.DockerClient(base_url='unix://var/run/docker.sock',timeout=10)
        try:
            client = docker.DockerClient(base_url="tcp://%s:6666" % ip, timeout=10)
            exist = client.containers.list(filters={"name":"apiserver-proxy"})
            if exist:
                self.logger.debug(exist.pop().short_id)
                return
            proxy = client.containers.run(image='tecnativa/tcp-proxy', detach=True,
                                          name="apiserver-proxy",
                                          restart_policy={"Name","always"},
                                          environment={"LISTEN": ":8443",
                                                       "TIMEOUT_TUNNEL":"1800s",
                                                       "TALK": " ".join([x + ":6443" for x in self.Masters])},
                                          ports={'8443/tcp': 8443})
            state = proxy.status
            while state != "running":
                self.logger.debug("proxy: %s -> %s"%(proxy.short_id,state))
                time.sleep(10)
                state = client.containers.get("apiserver-proxy").status
        except Exception as e:
            self.logger.error(e)
            sys.exit(-1)

    def __CreateConfig(self):
        name, _ = self.LoadBalancer.split(':')
        certs = set(self.Masters)
        certs.add(name)
        ClusterConfig = dict(apiVersion='kubeadm.k8s.io/v1beta1', kind='ClusterConfiguration',
                             etcd=dict(local=dict(imageRepository='gcr.azk8s.cn/google_containers',
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
                             imageRepository='gcr.azk8s.cn/google_containers',
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
            yaml.safe_dump_all([ClusterConfig, KubeProxy, KubeLet], stream=f, encoding="utf-8", allow_unicode=True,
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
        get = ret.split(" ")
        token = get[get.index("--token") + 1]
        Certhash = get[get.index("--discovery-token-ca-cert-hash") + 1]
        self.logger.debug(get)
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
            wait([pool.submit(self.__MakeProxyFromDockerSdk, ip) for ip in self.Masters], timeout=3600,
                 return_when=ALL_COMPLETED)

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
                state, _ = k8s.runner("kubectl get nodes|awk '/%s/{print $3}'" % self.Nodes[ip])
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
        self.__CopyCrts(self.Masters[0], fail)
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
        self.logger.debug("ips: %s -> doing: %s", ips, lst)
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
            wait([pool.submit(self.__MakeProxyFromDockerSdk, i) for i in DoIpList], timeout=3600, return_when=ALL_COMPLETED)
        self.logger.info(u"添加node节点进k8s里！！")
        with ThreadPoolExecutor() as pool:
            ret = [pool.submit(self.__JoinNode, ip) for ip in DoIpList]
        wait(ret, timeout=300, return_when=ALL_COMPLETED)
        for ojs in ret:
            self.logger.debug(ojs.result())
        self.logger.info("添加节点成功！！等待k8s初始化好节点。")

    def __canal(self, kubectl):
        self.logger.info(u"开始安装canal到k8s里")
        os.chdir(self.ScriptPath)
        self.subPopen('''sed -i 's#PODADDRESS#%s#' ./k8s/canal/canal.yaml''' % self.PodCidr)
        ssh = self.SSH(kubectl)
        ssh.mkdirs('/tmp/canal')
        self._SSL_sender("./k8s/canal", '/tmp/canal', kubectl)
        ssh.runner('kubectl create -f /tmp/canal')
        self.logger.info("canal install successfully!")

    def _dashboard(self, kubectl):
        self.logger.info(u"开始安装kube-dashboard")
        os.chdir(self.ScriptPath)
        tmp = '/tmp/dashboard'
        ssh = self.SSH(kubectl)
        ssh.mkdirs(tmp)
        self._SSL_sender("./k8s/dashboard", '/tmp/dashboard', kubectl)
        ssh.runner('kubectl create -f /tmp/dashboard')
        self.CheckRuning(name="dashboard", ip=kubectl)

    def _MetricServer(self, ip):
        self.logger.info(u"开始安装metric-server到k8s里")
        config = dict(apiService=dict(create=True),extraArgs={
            "kubelet-insecure-tls": True,
            "kubelet-preferred-address-types":"InternalIP,ExternalIP,Hostname"
        })
        Config = os.path.join(self.tmp, 'metrics-server.yaml')
        with open(Config,mode="wt") as fd:
            yaml.safe_dump(config,fd,encoding="utf-8", allow_unicode=True,default_flow_style=False)
        with self.SSH(ip) as ssh:
            ssh.push(Config,"/root/metrics-server.yaml",ip)
        with self.SSH(ip) as ssh:
            return ssh.runner("/usr/bin/helm install metrics-server -f /root/metrics-server.yaml bitnami/metrics-server --namespace=kube-system")

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

    def _helm(self, kubectl):
        self.logger.info("开始安装helm程序")
        ssh = self.SSH(kubectl)
        ssh.push("./k8s/helm/helm", "/usr/bin/helm", kubectl)
        ssh.runner(r"chmod a+x /usr/bin/helm")
        ssh.runner("/usr/bin/helm repo add stable http://mirror.azure.cn/kubernetes/charts/")
        ssh.runner("/usr/bin/helm repo add bitnami https://charts.bitnami.com/bitnami")
        ssh.runner("/usr/bin/helm repo update")
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
                "helm install -f /root/nginxvalue.yaml nginx --namespace nginx bitnami/nginx-ingress-controller")
            self.logger.info(u"重启kube-proxy，防止容器卡死")
            ssh.do_script(
                '''for i in $(kubectl -n kube-system get pods  -l k8s-app=kube-proxy|awk '/kube-proxy/{print $1}');do kubectl -n kube-system delete pod $i;done''')
        self.logger.info(u"Ingress安装成功")


    def Addons(self):
        ip = self.Masters[0]
        switchlist = {
            "ceph": self._rook,
            "prometheus": self._Prometheus
        }
        self.__canal(ip)
        self._dashboard(ip)
        self._helm(ip)
        self._MetricServer(ip)
        # for plugin in self.Plugins:
        #     switchlist[plugin](ip)
        # self.__IngressNginx(ip)

    def __Reset(self, ip):
        with self.SSH(ip) as ssh:
            ssh.do_script("kubeadm reset --force")
            ssh.runner("systemctl stop docker")

    def Remove(self):
        with ThreadPoolExecutor(max_workers=10) as th:
            wait([th.submit(self.__Reset, ip) for ip in self.ALL_IP], timeout=3600, return_when=ALL_COMPLETED)
