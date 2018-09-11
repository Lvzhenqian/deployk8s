#!/usr/bin/env python
# coding:utf-8
import  multiprocessing,os,json,sys

from functools import wraps
from .Base import BaseObject
from tempfile import mktemp


Locker = multiprocessing.Lock()
def templates(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        with Locker:
            if os.path.exists(BaseObject.tmp):
                os.chdir(BaseObject.tmp)
            else:
                os.makedirs(BaseObject.tmp)
                os.chdir(BaseObject.tmp)
            for files in os.listdir(BaseObject.tmp):
                os.remove(files)
            ret = fn(*args, **kwargs)
            for files in os.listdir(BaseObject.tmp):
                os.remove(files)
            return ret

    return wrap
class kubernetes(BaseObject):

    def _docker(self, node_ip):
        self.logger.info(u"{ip}安装docker！！".format(ip=node_ip))
        ssh = self.SSH(node_ip)
        ssh.do_script('/bin/bash %s'%os.path.join(kubernetes.KUBE_BINS,'env.sh'), timeout=3600)
        ssh.mkdirs(kubernetes.DOCKER_DATA)
        cmd2 = "sed -i 's@^ExecStart.*$@ExecStart=/usr/bin/dockerd --data-root {docker} --log-level=info@' " \
               "/lib/systemd/system/docker.service".format(docker=kubernetes.DOCKER_DATA)
        ssh.runner(cmd2)
        ssh.runner('systemctl daemon-reload')
        ssh.runner('systemctl restart docker')
        ssh.runner('systemctl status docker')
        self._Systemd_Check(node_ip, 'docker')

    def load_env(self):

        self.logger.info(u"复制BIN文件！！")
        for ip in self.ALL_IP:
            ssh = self.SSH(ip)
            ssh.mkdirs(kubernetes.KUBE_BINS)
            ssh.mkdirs(kubernetes.KUBE_SSL)
            self._SSL_sender(os.path.join(self.ScriptPath, 'k8s/all'), kubernetes.KUBE_BINS, ip)
            self._docker(ip)
            ssh.runner("chmod a+x %s/*" % kubernetes.KUBE_BINS)

    @templates
    def make_CA_files(self):
        self.logger.debug(u"生成CA证书！！")
        sslpath = mktemp()
        CA_CONFIG = {"signing": {"default": {"expiry": "8760h"}, "profiles": {"kubernetes": {"expiry": "8760h",
                                                                                             "usages": ["signing",
                                                                                                        "key encipherment",
                                                                                                        "server auth",
                                                                                                        "client auth"]}}}}
        CA_CSR = {"CN": "kubernetes", "key": {"algo": "rsa", "size": 2048},
                  "names": [{"C": "CN", "L": "BeiJing", "ST": "BeiJing", "O": "k8s", "OU": "System"}]}
        with open('./ca-config.json', mode='w') as ca_conf:
            json.dump(CA_CONFIG, ca_conf)
        with open('./ca-csr.json', mode='w') as ca_csr:
            json.dump(CA_CSR, ca_csr)
        client = self.cfg['ETCD']['IPS'][0]
        ssh = self.SSH(client)
        remote = mktemp()
        ssh.mkdirs(remote)
        self._SSL_sender(kubernetes.tmp, remote, client)
        cmd = "cd {tmp} && {KUBE_BINS}/cfssl gencert -initca ca-csr.json | {KUBE_BINS}/cfssljson -bare ca".format(
            tmp=remote, KUBE_BINS=kubernetes.KUBE_BINS)
        ssh.runner(cmd)
        if os.path.exists(sslpath):
            for files in os.listdir(sslpath):
                os.remove(os.path.join(sslpath, files))
        ssh.get_all(remote, sslpath)
        del ssh
        for files in os.listdir(sslpath):
            for ip in self.ALL_IP:
                ssh = self.SSH(ip)
                ssh.mkdirs(kubernetes.KUBE_SSL)
                src = os.path.join(sslpath, files)
                dst = os.path.join(kubernetes.KUBE_SSL, files)
                self.logger.debug("src:%s --> dst:%s ip:%s" % (src, dst, ip))
                ssh.push(src, dst, ip)

    @templates
    def _etcd(self, node_name, node_ip):
        self.logger.debug(u"{ip}: 安装etcd ！！".format(ip=node_ip))
        j = {"CN": "etcd", "hosts": ["127.0.0.1", str(node_ip)], "key": {"algo": "rsa", "size": 2048},
             "names": [{"C": "CN", "ST": "BeiJing", "L": "BeiJing", "O": "k8s", "OU": "System"}]}
        self.logger.debug(j)
        with open('./etcd-csr.json', mode='w') as jsfile:
            json.dump(j, jsfile)
        unit = '''[Unit]
Description=Etcd with docker
After=network.target
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/coreos

[Service]
Restart=always
RestartSec=5s
TimeoutStartSec=0
LimitNOFILE=65536
ExecStart=/usr/bin/docker run \\
  --rm \\
  --net=host \\
  --name etcd-v3.3.9 \\
  --volume={ETCD_DATA}:/etcd-data \\
  --volume={KUBE_SSL}:/ssl \\
  registry.matchvs.com/k8s/etcd:v3.3.9 \\
  /usr/local/bin/etcd \\
  --name {NODE_NAME} \\
  --data-dir /etcd-data \\
  --listen-client-urls https://{NODE_IP}:2379 \\
  --advertise-client-urls https://{NODE_IP}:2379 \\
  --listen-peer-urls https://{NODE_IP}:2380 \\
  --initial-advertise-peer-urls https://{NODE_IP}:2380 \\
  --initial-cluster {ETCD_NODES} \\
  --initial-cluster-token Matchvs-etcd-cluster \\
  --initial-cluster-state new \\
  --client-cert-auth \\
  --trusted-ca-file /ssl/ca.pem \\
  --cert-file /ssl/etcd.pem \\
  --key-file /ssl/etcd-key.pem \\
  --peer-client-cert-auth \\
  --peer-trusted-ca-file /ssl/ca.pem \\
  --peer-cert-file /ssl/etcd.pem \\
  --peer-key-file /ssl/etcd-key.pem 
ExecStop=/usr/bin/docker stop etcd-v3.3.9
[Install]
WantedBy=multi-user.target'''.format(ETCD_NODES=','.join(self.etcd_node), ETCD_DATA=kubernetes.ETCD_DATA,
                                     KUBE_SSL=kubernetes.KUBE_SSL, NODE_IP=node_ip, NODE_NAME=node_name)
        with open('./etcd.service', mode='w') as fd:
            fd.write(unit)
        cmd = 'cd {KUBE_SSL} && {KUBE_BINS}/cfssl gencert -ca={KUBE_SSL}/ca.pem -ca-key={KUBE_SSL}/ca-key.pem ' \
              '-config={KUBE_SSL}/ca-config.json ' \
              '-profile=kubernetes {KUBE_SSL}/etcd-csr.json | {KUBE_BINS}/cfssljson -bare etcd '.format(
            KUBE_SSL=kubernetes.KUBE_SSL, KUBE_BINS=kubernetes.KUBE_BINS)
        ssh = self.SSH(node_ip)
        ssh.mkdirs(kubernetes.ETCD_DATA)
        self._SSL_sender(self.tmp, kubernetes.KUBE_SSL, node_ip)
        ssh.runner(cmd)
        ssh.runner('systemctl daemon-reload')
        ssh.runner('systemctl start etcd')
        ssh.runner('systemctl enable etcd')

    @templates
    def make_kubectl(self):
        self.logger.info(u"安装kubctl命令行工具！！")
        js = {"CN": "admin", "hosts": [], "key": {"algo": "rsa", "size": 2048},
              "names": [{"C": "CN", "ST": "BeiJing", "L": "BeiJing", "O": "system:masters", "OU": "System"}]}
        with open('./admin-csr.json', mode='w') as fd:
            json.dump(js, fd)
        cmd = "cd {KUBE_SSL} && {KUBE_BINS}/cfssl gencert -ca={KUBE_SSL}/ca.pem -ca-key={KUBE_SSL}/ca-key.pem" \
              " -config={KUBE_SSL}/ca-config.json " \
              "-profile=kubernetes {KUBE_SSL}/admin-csr.json | {KUBE_BINS}/cfssljson -bare admin".format(
            KUBE_SSL=kubernetes.KUBE_SSL, KUBE_BINS=kubernetes.KUBE_BINS)

        cmd1 = "{KUBE_BINS}/kubectl config set-cluster kubernetes --certificate-authority={KUBE_SSL}/ca.pem " \
               "--embed-certs=true --server={KUBE_APISERVER} ".format(KUBE_SSL=kubernetes.KUBE_SSL,
                                                                      KUBE_BINS=kubernetes.KUBE_BINS,
                                                                      KUBE_APISERVER=self.cfg['NODES']['APISERVER_URL'])
        cmd2 = "{KUBE_BINS}/kubectl config set-credentials admin --client-certificate={KUBE_SSL}/admin.pem " \
               "--embed-certs=true --client-key={KUBE_SSL}/admin-key.pem --token={BOOTSTRAP_TOKEN} ".format(
            KUBE_SSL=kubernetes.KUBE_SSL,
            KUBE_BINS=kubernetes.KUBE_BINS,
            BOOTSTRAP_TOKEN=self.cfg['BOOTSTRAP_TOKEN'])
        cmd3 = "{KUBE_BINS}/kubectl config set-context kubernetes --cluster=kubernetes --user=admin".format(
            KUBE_BINS=kubernetes.KUBE_BINS)
        cmd4 = "{KUBE_BINS}/kubectl config use-context kubernetes".format(KUBE_BINS=kubernetes.KUBE_BINS)

        pathload = 'echo "export PATH=\$PATH:%s" >> /root/.bashrc' % kubernetes.KUBE_BINS
        for ip in self.ALL_IP:
            self._SSL_sender(kubernetes.tmp, kubernetes.KUBE_SSL, ip)
        else:
            for ip in self.ALL_IP:
                ssh = self.SSH(ip)
                ssh.runner(cmd)
                ssh.runner(cmd1)
                ssh.runner(cmd2)
                ssh.runner(cmd3)
                ssh.runner(cmd4)
                ssh.runner(pathload)

    @templates
    def _apiserver(self, node_ip):
        self.logger.info(u"{ip}安装apiserver！！".format(ip=node_ip))
        js = {"CN": "kubernetes", "hosts": [
            "127.0.0.1", node_ip, self.cfg['NODES']['APISERVER'],
            kubernetes.CLUSTER_DNS_SVC_IP,
            kubernetes.CLUSTER_KUBERNETES_SVC_IP, "kubernetes",
            "kubernetes.default", "kubernetes.default.svc", "kubernetes.default.svc.cluster",
            "kubernetes.default.svc.cluster.local"],
              "key": {"algo": "rsa", "size": 2048},
              "names": [{"C": "CN", "ST": "BeiJing", "L": "BeiJing", "O": "k8s", "OU": "System"}]}
        with open('./kubernetes-csr.json', mode='w') as fd:
            json.dump(js, fd)
        with open('./token.csv', mode='w') as fd:
            fd.write('{BOOTSTRAP_TOKEN},kubelet-bootstrap,10001,"system:kubelet-bootstrap"'.format(
                BOOTSTRAP_TOKEN=self.cfg['BOOTSTRAP_TOKEN']))
        unit = '''[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target
[Service]
ExecStart={KUBE_BINS}/kube-apiserver \\
  --admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota \\
  --advertise-address={NODE_IP} \\
  --bind-address={NODE_IP} \\
  --secure-port={secure_port} \\
  --insecure-bind-address={NODE_IP} \\
  --insecure-port={insecure_port} \\
  --authorization-mode=Node,RBAC \\
  --runtime-config=rbac.authorization.k8s.io/v1alpha1 \\
  --kubelet-https=true \\
  --enable-bootstrap-token-auth \\
  --token-auth-file={KUBE_SSL}/token.csv \\
  --service-cluster-ip-range={SERVICE_CIDR} \\
  --service-node-port-range={NODE_PORT_RANGE} \\
  --tls-cert-file={KUBE_SSL}/kubernetes.pem \\
  --tls-private-key-file={KUBE_SSL}/kubernetes-key.pem \\
  --client-ca-file={KUBE_SSL}/ca.pem \\
  --service-account-key-file={KUBE_SSL}/ca-key.pem \\
  --etcd-cafile={KUBE_SSL}/ca.pem \\
  --etcd-certfile={KUBE_SSL}/kubernetes.pem \\
  --etcd-keyfile={KUBE_SSL}/kubernetes-key.pem \\
  --etcd-servers={ETCD_ENDPOINTS} \\
  --enable-swagger-ui=true \\
  --allow-privileged=true \\
  --apiserver-count=2 \\
  --audit-log-maxage=30 \\
  --audit-log-maxbackup=3 \\
  --audit-log-maxsize=100 \\
  --audit-log-path=/var/log/audit.log \\
  --audit-policy-file={KUBE_BINS}/audit-policy.yaml \\
  --event-ttl=1h \\
  --logtostderr=true \\
  --v=0
Restart=on-failure
RestartSec=5
Type=notify
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target'''.format(NODE_IP=node_ip, KUBE_BINS=kubernetes.KUBE_BINS, KUBE_SSL=kubernetes.KUBE_SSL,
                                     ETCD_ENDPOINTS=','.join(self.etcd_endpoint),
                                     NODE_PORT_RANGE=kubernetes.NODE_PORT_RANGE,
                                     SERVICE_CIDR=kubernetes.SERVICE_CIDR,
                                     insecure_port=kubernetes.insecure_port,
                                     secure_port=kubernetes.secure_port)
        with open('./kube-apiserver.service', mode='w') as fd:
            fd.write(unit)
        cmd = 'cd {KUBE_SSL} && {KUBE_BINS}/cfssl gencert -ca={KUBE_SSL}/ca.pem -ca-key={KUBE_SSL}/ca-key.pem ' \
              '-config={KUBE_SSL}/ca-config.json ' \
              '-profile=kubernetes kubernetes-csr.json | {KUBE_BINS}/cfssljson -bare kubernetes '.format(
            KUBE_SSL=kubernetes.KUBE_SSL, KUBE_BINS=kubernetes.KUBE_BINS)
        self._SSL_sender(kubernetes.tmp, kubernetes.KUBE_SSL, node_ip)
        self._SSL_sender(os.path.join(self.ScriptPath, 'k8s/master'), kubernetes.KUBE_BINS, node_ip)
        ssh = self.SSH(node_ip)
        ssh.runner("chmod a+x %s/*" % kubernetes.KUBE_BINS)
        msg, state = ssh.runner(cmd)
        self.logger.debug(msg)
        ssh.runner('systemctl daemon-reload')
        ssh.runner('systemctl start kube-apiserver')
        ssh.runner('systemctl enable kube-apiserver')
        ssh.runner('systemctl status kube-apiserver')
        self._Systemd_Check(node_ip, 'kube-apiserver')

    @templates
    def _controller_manager(self, node_ip):
        self.logger.info(u"{ip}安装controller_manager！！".format(ip=node_ip))
        unit = '''[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
[Service]
ExecStart={KUBE_BINS}/kube-controller-manager \\
  --address=127.0.0.1 \\
  --master=http://{MASTER_URL}:{insecure_port} \\
  --allocate-node-cidrs=true \\
  --feature-gates=RotateKubeletServerCertificate=true \\
  --controllers=*,bootstrapsigner,tokencleaner \\
  --service-cluster-ip-range={SERVICE_CIDR} \\
  --cluster-cidr={CLUSTER_CIDR} \\
  --cluster-name=kubernetes \\
  --cluster-signing-cert-file={KUBE_SSL}/ca.pem \\
  --cluster-signing-key-file={KUBE_SSL}/ca-key.pem \\
  --service-account-private-key-file={KUBE_SSL}/ca-key.pem \\
  --root-ca-file={KUBE_SSL}/ca.pem \\
  --leader-elect=true \\
  --v=1
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target'''.format(KUBE_BINS=kubernetes.KUBE_BINS, KUBE_SSL=kubernetes.KUBE_SSL,
                                     MASTER_URL=self.cfg['NODES']['APISERVER'],
                                     CLUSTER_CIDR=kubernetes.CLUSTER_CIDR,
                                     SERVICE_CIDR=kubernetes.SERVICE_CIDR,
                                     insecure_port=kubernetes.insecure_port)
        with open('./kube-controller-manager.service', mode='w') as fd:
            fd.write(unit)
        ssh = self.SSH(node_ip)
        self._SSL_sender(kubernetes.tmp, kubernetes.KUBE_SSL, node_ip)
        ssh.runner('systemctl daemon-reload')
        ssh.runner('systemctl start kube-controller-manager')
        ssh.runner('systemctl enable kube-controller-manager')
        ssh.runner('systemctl status kube-controller-manager')
        self._Systemd_Check(node_ip, 'kube-controller-manager')

    @templates
    def _scheduler(self, node_ip):
        self.logger.info(u"{ip}安装scheduler！！".format(ip=node_ip))
        unit = '''[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
[Service]
ExecStart={KUBE_BINS}/kube-scheduler \\
  --address=127.0.0.1 \\
  --master=http://{MASTER_URL}:{insecure_port} \\
  --leader-elect=true \\
  --v=1
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target'''.format(KUBE_BINS=kubernetes.KUBE_BINS, MASTER_URL=self.cfg['NODES']['APISERVER'],
                                     insecure_port=kubernetes.insecure_port)

        with open('./kube-scheduler.service', mode='w') as fd:
            fd.write(unit)
        ssh = self.SSH(node_ip)
        self._SSL_sender(kubernetes.tmp, kubernetes.KUBE_SSL, node_ip)
        ssh.runner('systemctl daemon-reload')
        ssh.runner('systemctl start kube-scheduler')
        ssh.runner('systemctl enable kube-scheduler')
        ssh.runner('systemctl status kube-scheduler')
        self._Systemd_Check(node_ip, 'kube-scheduler')

    @templates
    def _kubelet(self, node_ip):
        self.logger.info(u"{ip}安装kubelet！！".format(ip=node_ip))
        ssh = self.SSH(node_ip)
        cmd1 = "{KUBE_BINS}/kubectl config set-cluster kubernetes --certificate-authority={KUBE_SSL}/ca.pem " \
               "--embed-certs=true " \
               "--server={KUBE_APISERVER} --kubeconfig={KUBE_SSL}/bootstrap.kubeconfig ".format(
            KUBE_SSL=kubernetes.KUBE_SSL, KUBE_BINS=kubernetes.KUBE_BINS,
            KUBE_APISERVER=self.cfg['NODES']['APISERVER_URL'])
        cmd2 = "{KUBE_BINS}/kubectl config set-credentials kubelet-bootstrap --token={BOOTSTRAP_TOKEN} " \
               "--kubeconfig={KUBE_SSL}/bootstrap.kubeconfig".format(KUBE_SSL=kubernetes.KUBE_SSL,
                                                                     KUBE_BINS=kubernetes.KUBE_BINS,
                                                                     BOOTSTRAP_TOKEN=self.cfg['BOOTSTRAP_TOKEN'])
        cmd3 = "{KUBE_BINS}/kubectl config set-context default --cluster=kubernetes --user=kubelet-bootstrap " \
               "--kubeconfig={KUBE_SSL}/bootstrap.kubeconfig ".format(KUBE_SSL=kubernetes.KUBE_SSL,
                                                                      KUBE_BINS=kubernetes.KUBE_BINS)
        cmd4 = "{KUBE_BINS}/kubectl config use-context default --kubeconfig={KUBE_SSL}/bootstrap.kubeconfig".format(
            KUBE_SSL=kubernetes.KUBE_SSL, KUBE_BINS=kubernetes.KUBE_BINS)
        ssh.runner(cmd1)
        ssh.runner(cmd2)
        ssh.runner(cmd3)
        ssh.runner(cmd4)
        unit = '''[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service
[Service]
WorkingDirectory={KUBELET_DATA}
ExecStart={KUBE_BINS}/kubelet \\
  --hostname-override=matchvs-{ExternalIP} \\
  --bootstrap-kubeconfig={KUBE_SSL}/bootstrap.kubeconfig \\
  --kubeconfig={KUBE_SSL}/kubelet.kubeconfig \\
  --root-dir={KUBELET_DATA} \\
  --register-node \\
  --pod-infra-container-image registry.matchvs.com/k8s/pause:3.1 \\
  --cert-dir={KUBE_SSL} \\
  --config={KUBE_SSL}/kubelet.config.json
  --logtostderr=true \\
  --network-plugin=cni \\
  --cni-conf-dir=/etc/cni/net.d \\
  --cni-bin-dir=/opt/cni/bin \\
  --v=1
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target'''.format(ExternalIP=self.cfg['NODES']['IPS'][node_ip],
                                     KUBE_BINS=kubernetes.KUBE_BINS, KUBE_SSL=kubernetes.KUBE_SSL,
                                     KUBELET_DATA=kubernetes.KUBELET_DATA)
        with open('./kubelet.service', mode='w') as fd:
            fd.write(unit)
        config = dict(kind="KubeletConfiguration",
                      apiVersion="kubelet.config.k8s.io/v1beta1",
                      authentication=dict(x509=dict(clientCAFile="%s/ca.pem" % kubernetes.KUBE_SSL),
                                          webhook=dict(enabled=False,cacheTTL= "2m0s"),anonymous=dict(enabled=True)),
                      authorization=dict(mode="AlwaysAllow",webhook=dict(cacheAuthorizedTTL="5m0s",cacheUnauthorizedTTL="30s")),
                      address=node_ip,port=10250,readOnlyPort=10255,cgroupDriver="cgroupfs",hairpinMode="promiscuous-bridge",
                      serializeImagePulls=False,RotateCertificates=True,
                      featureGates=dict(RotateKubeletClientCertificate= True,RotateKubeletServerCertificate= True),
                      MaxPods="512", failSwapOn=False, containerLogMaxSize="1Gi", containerLogMaxFiles=3,
                      clusterDomain="cluster.local.", clusterDNS=[kubernetes.CLUSTER_DNS_SVC_IP])
        with open('./kubelet.config.json',mode='w') as cfg:
            json.dump(config,cfg)
        ssh = self.SSH(node_ip)
        self._SSL_sender(kubernetes.tmp, kubernetes.KUBE_SSL, node_ip)
        self._SSL_sender(os.path.join(self.ScriptPath, 'k8s/nodes'), kubernetes.KUBE_BINS, node_ip)
        ssh.runner("chmod a+x %s/*" % kubernetes.KUBE_BINS)
        ssh.mkdirs(kubernetes.KUBELET_DATA)
        ssh.mkdirs(os.path.join(kubernetes.KUBELET_DATA,'config'))
        ssh.runner('systemctl daemon-reload')
        ssh.runner('systemctl start kubelet')
        ssh.runner('systemctl enable kubelet')
        ssh.runner('systemctl status kubelet')
        self._Systemd_Check(node_ip, 'kubelet')
        ssh.runner('echo "{ip} CalicoInterFace" >> /etc/hosts'.format(ip=node_ip))

    @templates
    def _kube_proxy(self, node_ip):
        self.logger.info(u"{ip}安装kube_proxy！！".format(ip=node_ip))
        js = {"CN": "system:kube-proxy", "hosts": [], "key": {"algo": "rsa", "size": 2048}, "names": [
            {"C": "CN", "ST": "BeiJing", "L": "BeiJing", "O": "k8s", "OU": "System"}]}
        with open('./kube-proxy-csr.json', mode='w') as fd:
            json.dump(js, fd)
        unit = '''[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target
[Service]
WorkingDirectory={KUBE_PROXY}
ExecStart={KUBE_BINS}/kube-proxy \\
  --config={KUBE_SSL}/kube-proxy.config.yaml \\
  --logtostderr=true \\
  --v=2
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target'''.format(KUBE_SSL=kubernetes.KUBE_SSL,
                                     KUBE_BINS=kubernetes.KUBE_BINS,KUBE_PROXY=kubernetes.KUBE_PROXY,)
        with open('./kube-proxy.service', mode='w') as fd:
            fd.write(unit)
        yaml = '''apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: {NODE_IP}
clientConnection:
  kubeconfig: {KUBE_SSL}/kube-proxy.kubeconfig
clusterCIDR: {SERVICE_CIDR}
healthzBindAddress: {NODE_IP}:10256
hostnameOverride: matchvs-{ExternalIP}
kind: KubeProxyConfiguration
metricsBindAddress: {NODE_IP}:10249
mode: "ipvs"      
'''.format(KUBE_SSL=kubernetes.KUBE_SSL,ExternalIP=self.cfg['NODES']['IPS'][node_ip],
           NODE_IP=node_ip, SERVICE_CIDR=kubernetes.SERVICE_CIDR)
        with open('kube-proxy.config.yaml',mode='w') as f:
            f.write(yaml)
        cmd = 'cd {KUBE_SSL} && {KUBE_BINS}/cfssl gencert -ca={KUBE_SSL}/ca.pem -ca-key={KUBE_SSL}/ca-key.pem' \
              ' -config={KUBE_SSL}/ca-config.json ' \
              '-profile=kubernetes kube-proxy-csr.json | {KUBE_BINS}/cfssljson -bare kube-proxy '.format(
            KUBE_SSL=kubernetes.KUBE_SSL, KUBE_BINS=kubernetes.KUBE_BINS)

        cmd1 = "cd {KUBE_SSL} && {KUBE_BINS}/kubectl config set-cluster kubernetes " \
               "--certificate-authority={KUBE_SSL}/ca.pem " \
               "--embed-certs=true --server={KUBE_APISERVER} --kubeconfig=kube-proxy.kubeconfig".format(
            KUBE_SSL=kubernetes.KUBE_SSL, KUBE_BINS=kubernetes.KUBE_BINS,
            KUBE_APISERVER=self.cfg['NODES']['APISERVER_URL'])

        cmd2 = "cd {KUBE_SSL} &&{KUBE_BINS}/kubectl config set-credentials kube-proxy" \
               " --client-certificate={KUBE_SSL}/kube-proxy.pem " \
               "--client-key={KUBE_SSL}/kube-proxy-key.pem --embed-certs=true " \
               "--kubeconfig=kube-proxy.kubeconfig".format(KUBE_SSL=kubernetes.KUBE_SSL,
                                                           KUBE_BINS=kubernetes.KUBE_BINS)

        cmd3 = "cd {KUBE_SSL} && {KUBE_BINS}/kubectl config set-context default " \
               "--cluster=kubernetes --user=kube-proxy " \
               "--kubeconfig=kube-proxy.kubeconfig".format(KUBE_SSL=kubernetes.KUBE_SSL,
                                                           KUBE_BINS=kubernetes.KUBE_BINS)
        cmd4 = "cd {KUBE_SSL} && {KUBE_BINS}/kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig".format(
            KUBE_SSL=kubernetes.KUBE_SSL, KUBE_BINS=kubernetes.KUBE_BINS)
        ssh = self.SSH(node_ip)
        self._SSL_sender(kubernetes.tmp, kubernetes.KUBE_SSL, node_ip)
        ssh.mkdirs(kubernetes.KUBE_PROXY)
        msg, state = ssh.runner(cmd)
        self.logger.debug(msg)
        ssh.runner(cmd1)
        ssh.runner(cmd2)
        ssh.runner(cmd3)
        ssh.runner(cmd4)
        ssh.runner('systemctl daemon-reload')
        ssh.runner('systemctl start kube-proxy')
        ssh.runner('systemctl enable kube-proxy')
        ssh.runner('systemctl status kube-proxy')
        self._Systemd_Check(node_ip, 'kube-proxy')

    def access_nodes(self, kubectl):
        cmd = "{KUBE_BINS}/kubectl get csr|grep Pending".format(KUBE_BINS=kubernetes.KUBE_BINS)
        ssh = self.SSH(kubectl)
        msg, state = ssh.runner(cmd)
        self.logger.debug(msg)
        pending = []
        if state:
            for lines in msg.split('\n'):
                if lines:
                    pending.append(lines.split()[0])
        self.logger.debug(pending)
        if pending:
            for p in pending:
                cmd2 = "{KUBE_BINS}/kubectl certificate approve {pending}".format(KUBE_BINS=kubernetes.KUBE_BINS,
                                                                                  pending=p)
                msg2 = ssh.runner(cmd2)
                self.logger.debug(msg2)

    def _dns(self, kubectl):
        ssh = self.SSH(kubectl)
        ssh.mkdirs('/tmp/dns')
        self._SSL_sender("./k8s/dns", '/tmp/dns', kubectl)
        ssh.runner('{KUBE_BINS}/kubectl create -f /tmp/dns'.format(KUBE_BINS=kubernetes.KUBE_BINS))
        self.CheckRuning(name="coredns", ip=kubectl)

    def _calico(self, kubectl):
        os.chdir(self.ScriptPath)
        cmd = '''sed -i -r '/CALICO_IPV4POOL_CIDR/{n;s#value: ".*"$#value: "%s"#}' %s''' % (
            kubernetes.CLUSTER_CIDR, './k8s/calico/calico.yaml')
        self.subPopen(cmd)
        ssh = self.SSH(kubectl)
        ssh.mkdirs('/tmp/calico')
        self._SSL_sender("./k8s/calico", '/tmp/calico', kubectl)
        ssh.runner('{KUBE_BINS}/kubectl create -f /tmp/calico'.format(KUBE_BINS=kubernetes.KUBE_BINS))
        self.logger.info("calico install successfully!")

    def _dashboard(self, kubectl):
        os.chdir(self.ScriptPath)
        tmp = '/tmp/dashboard'
        ssh = self.SSH(kubectl)
        ssh.mkdirs(tmp)
        self._SSL_sender("./k8s/dashboard", '/tmp/dashboard', kubectl)
        ssh.runner('{KUBE_BINS}/kubectl create -f /tmp/dashboard'.format(KUBE_BINS=kubernetes.KUBE_BINS))
        self.CheckRuning(name="dashboard", ip=kubectl)

    def _heapster(self, kubectl):
        ssh = self.SSH(kubectl)
        ssh.mkdirs('/tmp/heapster')
        self._SSL_sender("./k8s/heapster", '/tmp/heapster', kubectl)
        ssh.runner('{KUBE_BINS}/kubectl create -f /tmp/heapster'.format(KUBE_BINS=kubernetes.KUBE_BINS))
        self.CheckRuning(name="monitoring-influxdb", ip=kubectl)
        self.CheckRuning(name="heapster", ip=kubectl)
        self.CheckRuning(name="monitoring-grafana", ip=kubectl)

    def etcd(self):
        etcd_ips = {}
        self.logger.debug(etcd_ips)
        for index, ip in enumerate(list(set(self.cfg['ETCD']['IPS']))):
            index += 1
            name = "etcd0" + str(index)
            etcd_ips[name] = ip
            self.etcd_node.append(name + '=' + "https://" + ip + ':2380')
            self.etcd_endpoint.append("https://" + ip + ":2379")

        for name, ip in etcd_ips.items():
            self._etcd(name, ip)
        else:
            for ip in etcd_ips.values():
                self._Systemd_Check(ip, 'etcd.service')

    def master(self):
        for ip in self.cfg['ETCD']['IPS']:
            self._apiserver(ip)
            self._controller_manager(ip)
            self._scheduler(ip)
        else:
            ssh = self.SSH(self.cfg['ETCD']['IPS'][0])
            self.logger.info(u"开始生成kubelet-bootstrap rolebing！！")
            bootstrap = "{KUBE_BINS}/kubectl create clusterrolebinding kubelet-bootstrap " \
                        "--clusterrole=system:node-bootstrapper --user=kubelet-bootstrap".format(
                KUBE_BINS=kubernetes.KUBE_BINS)
            self.logger.debug(bootstrap)
            self.logger.debug(ssh.runner(bootstrap))
            self.logger.info(u"开始生成kubelet-nodes rolebing！！")
            n = "{KUBE_BINS}/kubectl create clusterrolebinding kubelet-nodes --clusterrole=system:node " \
                "--group=system:nodes".format(KUBE_BINS=kubernetes.KUBE_BINS)
            self.logger.debug(n)
            self.logger.debug(ssh.runner(n))

            msg, stat = ssh.runner("%s/kubectl get clusterrolebinding|awk '/kubelet/{print $1}'" % kubernetes.KUBE_BINS)
            if "kubelet-bootstrap" not in msg or "kubelet-nodes" not in msg:
                self.logger.error(u"生成rolebing失败！！")
                sys.exit(-1)
            else:
                self.logger.info(u"生成rollbing成功！！")
            return self.logger.info("master install successfully!")

    def node(self):
        hosts = []
        for key, value in self.cfg['NODES']['IPS'].items():
            hosts.append("{key} matchvs-{value}".format(key=key, value=value))
        self.logger.debug(hosts)
        ins = '\n'.join(hosts)
        self.logger.debug(ins)
        node_ips = set(self.cfg['NODES']['IPS'].keys())
        for ips in node_ips:
            IptableDrop = "/sbin/iptables -A INPUT -p tcp -m multiport --dports 10250,10251 -j DROP "
            new = self.SSH(ips)
            new.runner('echo "{ins}" >> /etc/hosts'.format(ins=ins))
            new.runner(IptableDrop)
            for dolist in node_ips:
                IptableAccept = "/sbin/iptables -I INPUT -s %s -p tcp -m multiport --dports 10250,10251 -j ACCEPT " % dolist
                new.runner(IptableAccept)
            LoAccept = "/sbin/iptables -I INPUT -i lo -j ACCEPT"
            new.runner(LoAccept)
            new.runner("service iptables save")
        else:
            for ip in node_ips:
                self._kubelet(ip)
                self._kube_proxy(ip)
            return self.logger.info("node install successfully!")

    def Deployment(self):
        ip = self.cfg['NODES']['IPS'].keys()[0]
        self.access_nodes(ip)
        self._calico(ip)
        self.CheckingNode(ip)
        self._dns(ip)
        self._dashboard(ip)
        self._heapster(ip)

    def DropEtcdService(self, ip):
        self.logger.info(u"{address}: 移除ETCD服务，并删除文件！".format(address=ip))
        ssh = self.SSH(ip)
        ssh.runner("systemctl stop etcd")
        ssh.runner("rm -rf /etc/systemd/system/etcd.service")
        ssh.runner("rm -rf {KUBE_SSL}".format(KUBE_SSL=self.KUBE_SSL))
        ssh.runner("rm -rf {ETCD_DATA}".format(ETCD_DATA=self.ETCD_DATA))
        ssh.runner("rm -rf {KUBE_BINS}".format(KUBE_BINS=self.KUBE_BINS))

    def DropDockerService(self, ip):
        self.logger.info(u"{address}: 卸载Docker服务，并删除文件！".format(address=ip))
        ssh = self.SSH(ip)
        ssh.runner("umount -f $(mount |awk '/kubelet/{print $3}')")
        ssh.runner('systemctl stop docker')


    def DropNodeService(self, ip):
        self.logger.info(u"{address}: 清理Node！！".format(address=ip))
        ssh = self.SSH(ip)
        ssh.runner("systemctl stop kube-apiserver")
        ssh.runner("systemctl stop kube-controller-manager")
        ssh.runner("systemctl stop kube-scheduler")
        ssh.runner("systemctl stop kubelet")
        ssh.runner("systemctl stop kube-proxy")
        ssh.runner("rm -rf /etc/systemd/system/kube*")
        ssh.runner("sed -i 's#.*{bins}$##g' /root/.bashrc".format(bins=kubernetes.KUBE_BINS))
        ssh.runner("rm -rf /root/.kube")
        ssh.runner("rm -rf {KUBE_SSL}".format(KUBE_SSL=self.KUBE_SSL))
        ssh.runner("rm -rf {KUBE_BINS}".format(KUBE_BINS=self.KUBE_BINS))
        ssh.runner("rm -rf {KUBELET_DATA}".format(KUBELET_DATA=self.KUBELET_DATA))
        ssh.runner("rm -rf {KUBE_PROXY}".format(KUBE_PROXY=self.KUBE_PROXY))
        ssh.runner("rm -rf /tmp/build.sh")
        ssh.runner("rm -rf /tmp/calico")
        ssh.runner("rm -rf /tmp/dashboard")
        ssh.runner("rm -rf /tmp/common")
        ssh.runner("rm -rf /tmp/heapster")
        ssh.runner("rm -rf /tmp/dns")
        ssh.runner("rm -rf /tmp/elk")
        ssh.runner("rm -rf /tmp/engine")
        ssh.runner("rm -rf /tmp/mysql")
        ssh.runner("rm -rf /tmp/nginx")
        ssh.runner("rm -rf /tmp/redis_cluster")
        ssh.runner("rm -rf /tmp/zk")

    def DropNfsService(self):
        self.logger.info(u"{address}: 移除NFS服务，并删除文件！".format(address=self.cfg['NFS']['IPS']))
        ssh = self.SSH(self.cfg['NFS']['IPS'])
        ssh.runner("systemctl stop nfs")
        ssh.runner("systemctl stop rpcbind")
        ssh.runner("yum remove rpcbind nfs-utils -y")
        ssh.runner("rm -rf /nfs")

    def remove(self):
        self.logger.info(u"开始删除kubernetes")
        self.DropNfsService()
        for ip in self.ALL_IP:
            self.DropEtcdService(ip)
            self.DropDockerService(ip)
            self.DropNodeService(ip)