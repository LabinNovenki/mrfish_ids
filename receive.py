# -*- coding: utf-8 -*-
from scapy.all import *
import pkt_parse
import connection_statistics as cs
import configparser as cp
import csv
import pandas as pd
from identify import Net
from identify import Net_nn
from identify import Rnn
import identify
import data_process as dp

global PAUSE
PAUSE = False
CLEAR = False
UPDATE_RECORD = False
CLASSIFIER = False


# 将报文p数据写入表格
def write_pkt(p, count):
    protocal = 'Unknown'
    if p.proto == 6:
        protocal = 'TCP'
    elif p.proto == 17:
        protocal = 'UDP'
    localtime = time.asctime(time.localtime(time.time()))
    with open("logs/log_pkt.csv", "a", newline="") as csvfile:
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


def clear_con_csv():
    with open("logs/log_con.csv", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["id", "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes",
                         "dbytes", "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss",
                         "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin",
                         "tcprtt", "synack", "ackdat", "smean", "dmean", "trans_depth",
                         "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
                         "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login",
                         "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst",
                         "is_sm_ips_ports", "Source", "Destination", "Time"])
    return


# 清空日志文件
if CLEAR:
    clear_con_csv()
    clear_pkt_csv()

# 打开配置文件,读取相关信息
config = cp.ConfigParser()
config.read('config/settings.ini', encoding='utf-8')
log_pkt_df = pd.read_csv("logs/log_pkt.csv")
log_con_df = pd.read_csv("logs/log_con.csv")

server_ip = config.get('sniffer', 'server_ip')
connecting_ip = {}
finished_connections = cs.Connection_set()
filter_str = "dst or src net %s" % server_ip
count_pkt = len(log_pkt_df)
count_con = len(log_con_df)


def handel_packet(pkt):  # p捕获到的数据包
    if PAUSE:
        print("sniff() pause.")
        while PAUSE:
            pass
    try:
        global count_con, count_pkt
        now = time.time()
        pkt[0].show()
        # 下面进行包的分配
        srcip = pkt[1].src
        dstip = pkt[1].dst
        # print('p.time=', p.time)
        connection = None
        if pkt.haslayer("UDP") or pkt.haslayer("TCP"):
            count_pkt += 1
            write_pkt(pkt, count_pkt)
            if srcip == server_ip and dstip in connecting_ip.keys():  # 服务器发往客户端
                if pkt[2].flags & 1 or pkt[2].flags & 2:
                    connection = connecting_ip[dstip]
                    connection.end_connection(pkt, now)
                    finished_connections.connection_ct_features(connection)
                    finished_connections.add_connection(connection)
                if pkt.haslayer('TCP'):
                    connection = connecting_ip[dstip]
                    connection.dst_to_src_pkt(pkt)
                elif pkt.haslayer('UDP'):
                    connection = pkt_parse.Connection(pkt)
                    connection.end_connection(pkt, now)
                    finished_connections.connection_ct_features(connection)
                    finished_connections.add_connection(connection)

            elif dstip == server_ip:  # 客户端发往服务器的包
                if pkt.haslayer('TCP'):
                    # 开始建立TCP的包
                    if pkt[2].flags & 2 and srcip not in connecting_ip.keys():
                        new_connection = pkt_parse.Connection(pkt)
                        connecting_ip[srcip] = new_connection
                        # TCP连接正常结束
                    elif pkt[2].flags & 1 and srcip in connecting_ip.keys():
                        connection = connecting_ip[srcip]
                        connection.src_to_dst_pkt(pkt)
                        connection.Dpkts += 2
                        connection.Spkts += 1
                        connection.end_connection(pkt, now)
                        finished_connections.connection_ct_features(connection)
                        finished_connections.add_connection(connection)
                        del connecting_ip[srcip]
                        # TCP连接异常结束
                    elif pkt[2].flags & 4 and srcip in connecting_ip.keys():
                        connection = connecting_ip[srcip]
                        connection.src_to_dst_pkt(pkt)
                        connection.end_connection(pkt, now)
                        finished_connections.connection_ct_features(connection)
                        finished_connections.add_connection(connection)
                        del connecting_ip[srcip]
                        # 其他包
                    else:
                        if srcip in connecting_ip.keys():
                            connection = connecting_ip[srcip]
                            connection.src_to_dst_pkt(pkt)
                elif pkt.haslayer('UDP'):
                    connection = pkt_parse.Connection(pkt)
                    finished_connections.connection_ct_features(connection)
                    finished_connections.add_connection(connection)
        if connection is not None:
            count_con += 1
            connection.output_to_csv(count_con)
            print("detecting...")
            in_features = connection.in_features()
            in_features = dp.connection_processing(in_features)
            res = identify.detect_rnn(in_features)
            if res.item() == 0 and CLASSIFIER:
                pass
                # TODO
            # print(in_features)
            print(res)
    except TypeError and AttributeError:
        pass


def start_sniff():
    # if UPDATE_RECORD:
    #     dp.data_processing("logs/log_con.csv")
    print("starting the program...")
    sniff(prn=handel_packet, count=0, filter=filter_str, timeout=60)
    print("sniff() finished.")

# start_sniff()