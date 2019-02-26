import toml


class Config(object):
    
    def __init__(self,selfFile):
        with open(selfFile,mode='r') as conf:
            self.cfg = toml.load(conf)

        self.Version = self.cfg['Kubeconf'].get('Version')
        self.LoadBalancer = self.cfg['Kubeconf'].get('LoadBalancer')
        if ":" not in self.LoadBalancer:
            self.LoadBalancer += ":443"
        self.KeepAlived = self.cfg['HA'].get('Enable')
        self.InterfaceName = self.cfg['HA'].get('InterfaceName')
        self.Vip = self.cfg['HA'].get('vip')
        self.ServiceCidr = self.cfg['Kubeconf'].get('ServiceCidr')
        self.PodCidr = self.cfg['Kubeconf'].get('PodCidr')
        self.InsecurePort = self.cfg['Kubeconf'].get('InsecurePort')
        self.NodePortRang = self.cfg['Kubeconf'].get('NodePortRang')
        self.DockerVersion = self.cfg['Kubeconf'].get('DockerVersion')
        self.DockerData = self.cfg['Kubeconf'].get('DockerData')
        self.EtcdData = self.cfg['Kubeconf'].get('EtcdData')
        self.KubeletData = self.cfg['Kubeconf'].get('KubeletData')
        self.ProxyMode = self.cfg['Kubeconf'].get('ProxyMode')
        self.HelmVersion = self.cfg['Kubeconf'].get('HelmVersion')
        self.Perfix = self.cfg['Kubeconf'].get('Perfix')
        self.Network = self.cfg['Kubeconf'].get('NetworkAddons')
        self.MTU = self.cfg['Kubeconf'].get('MTU')
        self.Metric = self.cfg['Kubeconf'].get('MetricAddons')
        self.token = self.cfg['Kubeconf'].get('Token')
        self.CertHash = self.cfg['Kubeconf'].get('CertHash')
        self.Masters = self.cfg['Master'].get('IPS')
        self.Nodes = self.cfg['Node']
        self.SshPort = self.cfg['Ssh'].get("Port")
        self.SshUsername = self.cfg['Ssh'].get("Username")
        self.SshPassword = self.cfg['Ssh'].get("Password")
        self.SshPkey = self.cfg['Ssh'].get("Pkey")
        self.SshPkeypass = self.cfg['Ssh'].get("Pkeypass")