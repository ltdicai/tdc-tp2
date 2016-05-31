#! /usr/bin/python
 # -*- coding: utf-8 -*-

import os
import sys
import argparse
import socket
import signal
import math
from scapy import utils
from scapy.all import IP, ICMP, sniff, sr, sr1, srp
from collections import defaultdict
from matplotlib import pyplot as plt
from matplotlib import figure
import numpy as np

def main(argv):
    print argv
    for i in xrange(1, 10):
        print "TTL:", i
        pkt = IP(dst=sys.argv[1], ttl=i) / ICMP()
        for j in xrange(1):
            res = sr1(pkt, timeout=5)
            print res

if __name__ == '__main__':
    try:
        if os.geteuid():
            print u"Tenés que correrlo con sudo"
            sys.exit(1)
    except (OSError, AttributeError):
        pass
    main(sys.argv)
