#!/usr/bin/env python
# coding:utf-8
import progressbar

class Progress(object):
    def __init__(self, ipaddress, name):
        self.bar = progressbar.ProgressBar()
        self.bar.widgets = [ipaddress, ": ", name, " ", progressbar.Percentage(),
                            progressbar.Bar(marker="#", left='[', right=']'),
                            progressbar.ETA(), " ", progressbar.FileTransferSpeed()]
        self.bar.start()

    def update(self, pos, total):
        self.bar.maxval = total
        self.bar.update(pos)

    def __del__(self):
        self.bar.finish()