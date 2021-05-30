# 服务器端运行，抓包并发送至解析机器
from scapy.all import *
import scapy.layers.inet
import pandas as pd
import numpy as np
import csv
import configparser as cp
import time

# 打开配置文件
config = cp.ConfigParser()
config.read('config/settings.ini', encoding='utf-8')

# 服务器ip地址
server_ip = config.get('sniffer', 'server_ip')
# 处理机ip地址
handle_ip = config.get('sniffer', 'handle_ip')
filter_str = "dst or src net %s" %server_ip

# 输出文件
count = 1

# 参数读取
max_n = int(config.get('sniffer', 'max_n'))  # 抓包的数量上限，设置为0时为无上限
time_out = config.get('sniffer', 'time_out')  # 抓包的时限，设置为None时无时间限制
if time_out == 'None':
    time_out = None
else:
    time_out = int(time_out)


# 将报文p数据写入表格
def write_pkt(p):
    global count
    protocal = 'Unknown'
    if p.proto == 6:
        protocal = 'TCP'
    elif p.proto == 17:
        protocal = 'UDP'
    localtime = time.asctime(time.localtime(time.time()))
    with open("los/log_pkt.csv", "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        row = [count, localtime, p.src, p.dst, p.sport, p.dport, protocal]
        writer.writerow(row)
    return


# 清空报文日志
def clear_pkt_csv():
    with open("logs/log_pkt.csv", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["id", "Time", "Source", "Destination", "Sport", "Dport", "Protocal"])
    return


def handelPacket(p):  # p捕获到的数据包
    global count
    #print("——————————————————————————————————————————————————————————————————————————————————————————————————————")

    if p.haslayer("UDP") or p.haslayer("TCP"):
        #output1 = {'time': time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime()))}
        #print(output1)
        #p.show()

        p.show()
        write_pkt(p)
        myip = scapy.layers.inet.IP(src=server_ip, dst=handle_ip)
        mytcp = scapy.layers.inet.TCP(sport=1024, dport=65535)
        pkt = myip/mytcp/p[0]
        send(pkt)
        count += 1
        #print("___________________________________________________")


#sniff(prn=handelPacket, count=-1, filter=filter_str)
sniff(prn=handelPacket, count=max_n, filter=filter_str, timeout=time_out)
