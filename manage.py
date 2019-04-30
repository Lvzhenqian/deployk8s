# coding:utf-8
import sys,os
from script.kubernetes import kubernetes

class Manager(kubernetes):
    def __init__(self,conf):
        self.ScriptPath = os.getcwd()
        super(Manager,self).__init__(conf)

    def Init(self):
        # 初始化检查
        self.InitCheck()
        # 初始化服务器配置与参数等
        self.MakeInitPath()

    def Install(self):
        try:
            # 环境配置
            self.MakeAll()
            # 增加master
            self.MakeMaster()
            # 去除master节点调度策略
            self.SchedulerToMaster()
            # 增加node
            self.AddNode()
            # 安装插件
            self.Addons()
        except KeyboardInterrupt as e:
            self.logger.error(u"用户手动退出！%s"%e)
        except Exception as e:
            self.logger.error(e)
            sys.exit(0)
    def remove(self):
        self.logger.info(u"开始删除kubernetes")
        self.remove()


if __name__ == '__main__':
    args = sys.argv
    args.pop(0)
    if len(args) > 0 and os.path.isfile(args[0]):
        cfg = args.pop(0)
    else:
        cfg = "./config.toml"
    kube = Manager(os.path.realpath(cfg))
    if args and hasattr(kube, args[0]):
        func = args.pop(0)
        if len(args) == 1:
            getattr(kube, func)(args.pop())
        else:
            getattr(kube, func)(*args)
        sys.exit(0)
    else:
        print '''[Usage]:
    ./pyenv/bin/python manage.py Init （初始化服务器与安装相应的rpm包）
    ./pyenv/bin/python manage.py Install （安装k8s集群）
    ./pyenv/bin/python manage.py ExtendEnv （扩展节点时安装节点基础环境）
    ./pyenv/bin/python manage.py AddNode  （添加扩展节点到k8s里）
    '''