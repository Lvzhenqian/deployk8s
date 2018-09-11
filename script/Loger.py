#!/usr/bin/env python
# coding:utf-8
import logging
from colorlog import ColoredFormatter
import sys

LOGLEVE = logging.INFO
LOGFORMAT = ColoredFormatter(
    fmt='[%(asctime)s]:%(log_color)s[%(funcName)s]:%(lineno)d:%(levelname)s%(reset)s:%(message_log_color)s%(message)s',
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

DEBUG = logging.DEBUG
INFO = logging.INFO
getLogger = logging.getLogger
file_hand = logging.FileHandler(filename='install.log', mode='w')
file_hand.setFormatter(LOGFORMAT)
CONSOLE_FMT = ColoredFormatter(fmt='%(log_color)s%(message)s%(reset)s')
console = logging.StreamHandler(stream=sys.stdout)
console.setFormatter(CONSOLE_FMT)
console.setLevel(LOGLEVE)

