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
global output_str
output_str = ''


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
        row = [count, localtime, p["IP"].src, p["IP"].dst, p.sport, p.dport, protocal]
        output = "id\ttime\tsrc\tdst\tsport\tdport\tprotocal" + '\n' + str(row)
        # window.textEdit.setText(output)
        # window.textEdit.viewport().update()
    return


# 清空报文日志
def clear_pkt_csv():
    with open("logs/log_pkt.csv", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["id", "Time", "Source", "Destination", "Sport", "Dport", "Protocal"])
    return


# 清空连接日志
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
                         "is_sm_ips_ports", "Source", "Destination", "Time", "label", "attack_cat"])
    return


# 清空攻击连接日志
def clear_atk_csv():
    with open("logs/log_atk.csv", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["id", "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes",
                         "dbytes", "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss",
                         "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin",
                         "tcprtt", "synack", "ackdat", "smean", "dmean", "trans_depth",
                         "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
                         "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login",
                         "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst",
                         "is_sm_ips_ports", "Source", "Destination", "Time", "label", "attack_cat"])
    return


# 打开配置文件,读取相关信息
config = cp.ConfigParser()
config.read('config/settings.ini', encoding='utf-8')
log_pkt_df = pd.read_csv("logs/log_pkt.csv")
log_con_df = pd.read_csv("logs/log_con.csv")

server_ip = config.get('sniffer', 'server_ip')
connecting_ip = {}
finished_connections = cs.Connection_set()
filter_str = "dst or src net %s" % server_ip


CLEAR = bool(int(config.get('sniffer', 'CLEAR')))
UPDATE_RECORD = bool(int(config.get('sniffer', 'UPDATE')))
CLASSIFIER = bool(int(config.get('sniffer', 'CLASSIFIER')))
MOD = int(config.get('sniffer', 'MOD'))

if not CLEAR:
    count_pkt = len(log_pkt_df)
    count_con = len(log_con_df)
else:
    count_pkt = 0
    count_con = 0

count_ = int(config.get('sniffer', 'max_n'))
time_out = config.get('sniffer', 'timeout')
if time_out == 'None':
    time_out = None
else:
    time_out = int(time_out)


def connect_detect(connection):
    global count_con
    count_con += 1
    print("detecting...")
    in_features = connection.in_features()
    # print(in_features)
    in_features = dp.connection_processing(in_features)
    # print(in_features)
    if MOD == 1:
        res = identify.detect_cnn(in_features)
    elif MOD == 2:
        res = identify.detect_nn(in_features)
    else:
        res = identify.detect_rnn(in_features)
    connection.lable = res
    connection.attack_cat = 'Unknown'
    connection.output_to_csv(count_con, file='logs/log_con.csv')
    if res.item() == 1:
        print('There is a potential threat to this connection, which may cause damage to the network.')
        if CLASSIFIER:
            atk_cat = identify.detect_classify(in_features)
            ATK = ['Normal', 'Backdoor', 'Analysis', 'Fuzzers',
                   'Shellcode', 'Reconnaissance', 'Exploits',
                   'DoS', 'Worms', 'Generic']
            connection.attack_cat = ATK[atk_cat]
        connection.output_to_csv(count_con, file='logs/log_atk.csv')

        # TODO
    else :
        # print(in_features)
        print('safe connection detected.')


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
                    connect_detect(connection)
                    finished_connections.add_connection(connection)
                if pkt.haslayer('TCP'):
                    connection = connecting_ip[dstip]
                    connection.dst_to_src_pkt(pkt)
                elif pkt.haslayer('UDP'):
                    connection = pkt_parse.Connection(pkt)
                    connection.end_connection(pkt, now)
                    finished_connections.connection_ct_features(connection)
                    connect_detect(connection)
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
                        connect_detect(connection)
                        finished_connections.add_connection(connection)
                        del connecting_ip[srcip]
                        # TCP连接异常结束
                    elif pkt[2].flags & 4 and srcip in connecting_ip.keys():
                        connection = connecting_ip[srcip]
                        connection.src_to_dst_pkt(pkt)
                        connection.end_connection(pkt, now)
                        finished_connections.connection_ct_features(connection)
                        connect_detect(connection)
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
                    connect_detect(connection)
                    finished_connections.add_connection(connection)

    except TypeError and AttributeError:  # TypeError and AttributeError:
        pass


def start_sniff():
    # 清空日志文件
    if CLEAR:
        print("clearing log file...")
        clear_con_csv()
        clear_pkt_csv()
        clear_atk_csv()
    print("starting the program...")
    sniff(prn=handel_packet, count=count_, filter=filter_str, timeout=time_out)
    print("sniff() finished.")
    if UPDATE_RECORD:
        print("updating records file...")
        dp.data_processing("logs/log_con.csv")


# start_sniff()
