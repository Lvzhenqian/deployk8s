#!/usr/bin/env python
# coding:utf-8
from .ProgressBar import Progress
from .Loger import DEBUG, getLogger, file_hand
import paramiko, sys, select, os
from stat import S_ISDIR


class SSH(object):
    def __init__(self, host, port, user, passwd=None, pKey=None, keypass=None):
        self.logger = getLogger(name='SshClient')
        self.logger.propagate = False
        self.logger.setLevel(DEBUG)
        self.logger.addHandler(file_hand)
        self.address = (host, port)
        # self.logger.info(self.address)
        self.client = paramiko.Transport(self.address)
        if pKey:
            if keypass:
                key = paramiko.RSAKey.from_private_key_file(pKey, password=keypass)
            else:
                key = paramiko.RSAKey.from_private_key_file(pKey)
            self.client.connect(username=user, pkey=key)
        else:
            self.client.connect(username=user, password=passwd)
        self.sftp = paramiko.SFTPClient.from_transport(self.client)

    def runner(self, command, timeout=3600):
        ssh = paramiko.SSHClient()
        ssh._transport = self.client
        self.logger.debug("%s: %s", self.address[0], command)
        stdin, stdout, stderr = ssh.exec_command(command, get_pty=True, timeout=timeout)
        data = ''
        while True:
            try:
                out = stdout.readline()
                err = stderr.readline()
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.error(e)
                sys.exit(-1)
            if out == '' and err == '':
                break
            if err:
                self.logger.error(err)
                data += err
                return (data, 0)
            else:
                self.logger.info(out.strip('\n'))
                data += out
        return (data, 1) if data else ("", 0)

    def do_script(self, command, timeout=3600):
        self.logger.debug(command)
        ret = []
        channel = self.client.open_session(timeout=timeout)
        channel.get_pty()
        channel.exec_command(command)
        while not channel.exit_status_ready():
            try:
                rlist, wlist, xlist = select.select([channel], [], [], 1)
                if len(rlist) > 0:
                    recv = channel.recv(65533)
                    lines = recv.split('\n')
                    for s in lines:
                        if s:
                            line = s.strip('\r')
                            ret.append(line)
                            self.logger.info(line)
            except KeyboardInterrupt:
                channel.send("\x03")
                channel.close()
                self.client.close()
        return ret

    def mkdirs(self, path):
        return self.runner('mkdir -p %s' % path)

    def push(self, src, dst, ip=None):
        if os.path.isfile(src):
            bar = Progress(ipaddress=ip, name=os.path.basename(src))
            self.sftp.put(src, dst, callback=bar.update)
        else:
            try:
                self.sftp.mkdir(dst)
            except IOError:
                pass
            for name in os.listdir(src):
                srcname = os.path.join(src, name)
                dstname = os.path.join(dst, name)
                try:
                    if os.path.isdir(srcname):
                        self.push(srcname, dstname, ip)
                    else:
                        bar = Progress(ipaddress=ip, name=name)
                        self.sftp.put(srcname, dstname, callback=bar.update)
                        self.sftp.put(srcname, dstname)
                except Exception as e:
                    self.logger.error(e)

    def sftp_walk(self, remotepath):
        path = remotepath
        files = []
        folders = []
        for f in self.sftp.listdir_attr(remotepath):
            if S_ISDIR(f.st_mode):
                folders.append(f.filename)
            else:
                files.append(f.filename)
        # print(path, folders, files)
        yield path, folders, files
        for folder in folders:
            new_path = os.path.join(remotepath, folder)
            for x in self.sftp_walk(new_path):
                yield x

    def get(self, src, dst):
        return self.sftp.get(src, dst)

    def get_all(self, remotepath, localpath):
        self.sftp.chdir(os.path.split(remotepath)[0])
        parent = os.path.split(remotepath)[1]
        try:
            os.mkdir(localpath)
        except:
            pass
        for walker in self.sftp_walk(parent):
            # self.logger.info(walker)
            for file in walker[2]:
                self.logger.debug("src:%s --> dst:%s", os.path.join(walker[0], file), os.path.join(localpath, file))
                self.get(os.path.join(walker[0], file), os.path.join(localpath, file))

    def __del__(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger.error((exc_type,exc_val,exc_tb))
        return self.client.close()
