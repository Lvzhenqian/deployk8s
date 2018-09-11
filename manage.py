#!/usr/bin/env python
# coding:utf-8
from script.kubernetes import *
from datetime import datetime
reload(sys)
sys.setdefaultencoding('utf-8')

class Manager(kubernetes):
    def __init__(self,conf):
        self.ScriptPath = os.getcwd()
        super(kubernetes,self).__init__(conf)

    def Install(self):
        try:
            before = datetime.now()
            # 初始化检查
            self.InitCheck()
            # 复制bin文件到相应的目录
            self.load_env()
            # 生成ca证书
            self.make_CA_files()
            # 安装ETCD
            self.etcd()
            # 安装kubectl 命令行工具
            self.make_kubectl()
            # 安装master 服务
            self.master()
            # 安装node 服务
            self.node()
            # 安装dashboard、dns、calico等服务
            self.Deployment()
            after = datetime.now() - before
            self.logger.info("脚本执行时间：%s"%str(after))
        except KeyboardInterrupt, e:
            self.logger.error(u"用户手动退出！")

if __name__ == '__main__':
    args = sys.argv
    args.pop(0)
    kube = Manager('./config.toml')
    if args and hasattr(kube, args[0]):
        func = args.pop(0)
        if len(args) == 1:
            getattr(kube, func)(args.pop())
        getattr(kube, func)(*args)
    else:
        kube.Install()
