import toml,os


class Config(object):
    
    def __init__(self,selfFile):
        self.ConfPath = selfFile

        with open(self.ConfPath,mode='r') as conf:
            self.cfg = toml.load(conf)

        self.Version = self.cfg['Kubeconf'].get('Version',"1.13.6")
        self.BaseDataDir = self.cfg['Kubeconf'].get('DataDir',"/data/kubernetes")
        self.ServiceCidr = self.cfg['Kubeconf'].get('ServiceCidr',"10.254.0.0/16")
        self.PodCidr = self.cfg['Kubeconf'].get('PodCidr',"172.30.0.0/16")
        self.NodePortRang = self.cfg['Kubeconf'].get('NodePortRang',"30000-50000")
        self.DockerVersion = self.cfg['Kubeconf'].get('DockerVersion',"docker-ce-19.03.5-3.el7.x86_64")
        self.DockerData = os.path.join(self.BaseDataDir,"docker")
        self.EtcdData = os.path.join(self.BaseDataDir,"etcd")
        self.KubeletData = os.path.join(self.BaseDataDir,"kubelet")
        self.ProxyMode = self.cfg['Kubeconf'].get('ProxyMode',"ipvs")
        self.Perfix = ""
        self.MTU = self.cfg['Kubeconf'].get('MTU',"1440")
        self.token = self.cfg['Kubeconf'].get('Token')
        self.CertHash = self.cfg['Kubeconf'].get('CertHash')
        self.Nodes = self.cfg['Node']
        self.SshPort = self.cfg['Ssh'].get("Port",22)
        self.SshUsername = self.cfg['Ssh'].get("Username")
        self.SshPassword = self.cfg['Ssh'].get("Password")
        self.SshPkey = self.cfg['Ssh'].get("Pkey","")
        self.SshPkeypass = self.cfg['Ssh'].get("Pkeypass","")
        self.LoadBalancer = "127.0.0.1:8443"
        self.RegistryMirror = self.cfg["Kubeconf"].get("RegistryMirror","mirrorgooglecontainers")
        self.QuayioMirror = self.cfg["Kubeconf"].get("QuayioMirror","quay-mirror.qiniu.com")