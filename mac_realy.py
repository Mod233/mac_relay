from scapy.all import *

eth_dst = "\xff\xff\xff\xff\xff\xff"
eth_src = "\xaa\xaa\xaa\xaa\xaa\xaa"
debug = []

def raw():
    while True:
    # net interface name
        pkts = sniff(iface=None, count=1)
        for buf in pkts:
            data2 = str(buf)
#            print buf
            try:
#                if buf[IP].dst!='10.123.2.2' and buf[IP].src!='10.123.2.2':
#                    continue
                print "src ", buf[IP].src
                print "dst ", buf[IP].dst
            except Exception, e:
                print e.message
                continue
            eth_dst = data2[0:6]
            eth_src = data2[6:12]
            data = eth_src + eth_dst + data2[12:]
            sendp(data)


if __name__ == '__main__':
    raw()
