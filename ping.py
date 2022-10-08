import socket
import time

import scapy.all as scapy
from argparse import ArgumentParser
from time import sleep
from colorama import Fore, init
import logging
from os import urandom
import sys
init(autoreset=True)

parser = ArgumentParser()
parser.add_argument("dest", help="destination ip address")
parser.add_argument("-c", "--count", help="Packet count", type=int)
args = parser.parse_args()

logging.basicConfig(format="[+] %(level)s: %(message)s", level=logging.INFO)
logger = logging.getLogger("pinger")


def prepare(func):
    def wraps(dest, count):
        r_id = int.from_bytes(urandom(2), sys.byteorder)
        data = b"abcdefghijklmnopqrstuvwabcdefghi"
        func(dest, count, r_id=r_id, data=data)
    return wraps


def parse_response(res, ms):
    ip_layer = res[0].answer["IP"]
    icmp_layer = res[0].answer["ICMP"]
    return f"Reply from {ip_layer.src} bytes={len(icmp_layer.load)} time={'{:.0f}'.format(ms)}ms ttl={ip_layer.ttl}"


def ping_it(dest, **kwargs):
    packet = scapy.IP(dst=dest, id=kwargs["r_id"])/scapy.ICMP(id=1,seq=kwargs["seq"])/kwargs["data"]
    start = time.time()
    s, r = scapy.sr(packet, verbose=False, timeout=2)
    end = time.time()
    ms = (end-start)*1000
    res = parse_response(s, ms)
    print(res)


@prepare
def ping_loop(dest, count, **kwargs):
    try:
        seq = 0
        if count is not None:
            for _ in range(count):
                kwargs["seq"] = seq
                ping_it(dest, **kwargs)
                seq += 1
                sleep(1)
        else:
            while True:
                kwargs["seq"] = seq
                ping_it(dest, **kwargs)
                seq += 1
                sleep(1)
    except KeyboardInterrupt:
        logger.info(Fore.CYAN+"exiting", extra={"level": "info"})
        exit(0)
    except socket.gaierror:
        logger.error(Fore.RED + "unknown address", extra={"level": "error"})
        exit(0)
    except Exception as e:
        print(e)
        exit(0)
if __name__ == "__main__":
    ping_loop(args.dest, args.count)