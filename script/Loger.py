#!/usr/bin/env python
# coding:utf-8
import logging
from colorlog import ColoredFormatter
import sys

LOGLEVE = logging.INFO
LOGFORMAT = ColoredFormatter(
    fmt='%(log_color)s[%(threadName)s]:[%(funcName)s]:%(lineno)d:%(levelname)s%(reset)s:%(message_log_color)s%(message)s',
    log_colors={
        'DEBUG': 'blue',
        'INFO': 'green',
        'ERROR': 'red',
        'WARNING': 'yellow',
        'CRITICAL': 'red,bg_white',
    }, secondary_log_colors={
        'message': {
            'ERROR': 'red',
            'CRITICAL': 'red',
            'DEBUG': 'white',
            'INFO': 'white',
            'WARNING': 'yellow'
        }
    })

try:
    unicode
    _unicode = True
except NameError:
    _unicode = False

class CoustomFileHandler(logging.FileHandler):

    def __init__(self, filename, mode='a', encoding=None, delay=0):
        self.terminator="\n"
        super(CoustomFileHandler,self).__init__(filename, mode, encoding, delay)

    def emit(self, record):
        if self.stream is None:
            self.stream = self._open()
        try:
            msg = self.format(record)
            stream = self.stream
            fs = "%s"+self.terminator
            if not _unicode:
                stream.write(fs % msg)
            else:
                try:
                    if (isinstance(msg, unicode) and
                        getattr(stream, 'encoding', None)):
                        ufs = fs.decode(stream.encoding)
                        try:
                            stream.write(ufs % msg)
                        except UnicodeEncodeError:
                            stream.write((ufs % msg).encode(stream.encoding))
                    else:
                        stream.write(fs % msg)
                except UnicodeError:
                    stream.write(fs % msg.encode("UTF-8"))
            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)

DEBUG = logging.DEBUG
INFO = logging.INFO
getLogger = logging.getLogger
file_hand = CoustomFileHandler(filename='install.log', mode='w')
file_hand.terminator = "\n"
file_hand.setFormatter(LOGFORMAT)
CONSOLE_FMT = ColoredFormatter(fmt='%(log_color)s%(message)s%(reset)s')
console = logging.StreamHandler(stream=sys.stdout)
console.setFormatter(CONSOLE_FMT)
console.setLevel(LOGLEVE)

