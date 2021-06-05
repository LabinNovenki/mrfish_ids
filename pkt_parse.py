# 连接特征解析

from scapy.all import *
from scapy.layers import http
import pandas as pd
import numpy as np
import csv
import time




class Connection:
    def __init__(self, p):
        self.start_time = time.asctime(time.localtime(time.time()))
        self.srcip = ''
        self.sport = 0
        self.dstip = ''
        self.dsport = 0
        self.proto = ''
        self.state = ''
        self.dur = 0
        self.sbytes = 0
        self.dbytes = 0
        self.sttl = 0
        self.dttl = 0
        self.sloss = 0
        self.dloss = 0
        self.service = ''
        self.Sload = 0
        self.Dload = 0
        self.Spkts = 1
        self.Dpkts = 0
        self.swin = 0
        self.dwin = 0
        self.stcpb = 0
        self.dtcpb = 0
        self.smeansz = 0
        self.deansz = 0
        self.trans_depth = 0
        self.res_bdy_len = 0
        self.sjit = 0
        self.djit = 0
        self.Stime = 0
        self.Ltime = 0
        self.Sintpkt = 0
        self.Dintpkt = 0
        self.tcprtt = 0
        self.synack = 0
        self.ackdat = 0
        self.is_sm_ips_ports = 0
        self.ct_state_ttl = 0
        self.ct_flw_http_mthd = 0
        self.is_ftp_login = 0
        self.ct_ftp_cmd = 0
        self.ct_srv_src = 0
        self.ct_srv_dst = 0
        self.ct_dst_ltm = 0
        self.ct_src_ltm = 0
        self.ct_src_dport_ltm = 0
        self.ct_dst_sport_ltm = 0
        self.ct_dst_src_ltm = 0
        self.syn_ack_time = 0
        self.lable = 0
        self.attack_cat = 0

        ip = p.getlayer("IP")
        self.srcip = ip.src
        self.dstip = ip.dst
        self.sport = ip.sport
        self.dport = ip.dport
        self.Stime = p.time
        self.sbytes += len(p)

        # service特征

        if ip.proto == 6:
            self.proto = 'tcp'
        elif ip.proto == 17:
            self.proto = 'udp'
        self.sttl = ip.ttl

        if self.srcip == self.dstip and self.sport == self.dport:
            self.is_sm_ips_ports = 1
        if p.haslayer('TCP'):
            tcp = p.getlayer('TCP')
            if tcp.flags & 16:
                self.swin = tcp.window
            self.tcp_service(tcp)

        if p.haslayer('UDP'):
            udp = p.getlayer('UDP')
            self.udp_service(udp)

    def src_to_dst_pkt(self, p):
        ip = p.getlayer("IP")
        self.sbytes += len(p)
        self.Spkts += 1
        self.sttl = ip.ttl
        if p.haslayer('TCP'):
            tcp = p.getlayer('TCP')
            if tcp.flags & 16:
                self.swin = tcp.window
                if self.ackdat == 0:
                    self.ackdat = p.time - self.syn_ack_time
            self.stcpb = tcp.seq

            if p.haslayer(http.HTTPRequest) and (p[http.HTTPRequest].Method == b'POST' or
                                                 p[http.HTTPRequest].Method == b'GET'):
                self.ct_flw_http_mthd += 1

            if self.service == 'ftp':
                raw = p.spirntf('%Raw.load%')
                user = re.findall('(?i)USER (.*)', raw)
                pwd = re.findall('(?i)PASS (.*)', raw)
                if user or pwd:
                    self.is_ftp_login = 1
                    self.ct_ftp_cmd = 1

        if p.haslayer('UDP'):
            # TODO
            pass

    def dst_to_src_pkt(self, p):
        ip = p.getlayer("IP")
        self.dbytes += len(p)
        self.Dpkts += 1
        self.dttl = ip.ttl
        if p.haslayer('TCP'):
            tcp = p.getlayer('TCP')
            if tcp.flags & 16:
                self.dwin = tcp.window
                if tcp.flags & 2:
                    self.synack = p.time - self.Stime
                    self.syn_ack_time = p.time
            self.dtcpb = tcp.seq

        if p.haslayer('UDP'):
            # TODO
            pass

    def end_connection(self, p, now):

        if p.haslayer('TCP'):
            self.Ltime = p.time
            self.dur = self.Ltime - self.Stime
            if self.dur != 0:
                self.Sintpkt = self.Spkts / self.dur
                self.Dintpkt = self.Dpkts / self.dur
        if p.haslayer('UDP'):
            self.Ltime = now
            self.Sintpkt = self.dur * 1000

        self.dur = self.Ltime - self.Stime
        self.Sload = self.sbytes / self.dur
        self.Dload = self.dbytes / self.dur

    def tcp_service(self, tcp):
        http_port = [80, 8080, 3128, 8081, 9080]
        if tcp.dport in http_port:
            self.service = 'http'
        elif tcp.dport == 443:
            self.service = 'ssl'
        elif tcp.dport == 21:
            self.service = 'ftp'
        elif tcp.dport == 20:
            self.service = 'ftp-data'
        elif tcp.dport == 25:
            self.service = 'smtp'
        elif tcp.dport == 22:
            self.service = 'ssh'
        elif tcp.dport == 161:
            self.service = 'snmp'
        elif tcp.dport == 68:
            self.service = 'dhcp'
        elif tcp.dport == 194:
            self.service = 'irc'
        elif tcp.dport == 110:
            self.service = 'pop3'
        else:
            self.service = '-'

    def udp_service(self, udp):
        if udp.dport == 53:
            self.service = 'dns'
        elif udp.dport == 1812 or udp.sport == 1813:
            self.service = 'radius'
        else:
            self.service = '-'

    def output_to_csv(self, count, file):
        """
        将本次连接的特征以.csv文件形式输出
        :return:
        """
        with open(file, "a", newline="") as csvfile:
            writer = csv.writer(csvfile)
            row = [count, self.dur, self.proto, self.service, 1.8620, self.Spkts, self.Dpkts,
                   self.sbytes, self.dbytes, 82410.88, self.sttl, self.dttl, self.Sload,
                   self.Dload, 4.7536, 6.3085, self.Sintpkt, self.Dintpkt, 6363.0750,
                   535.18043, self.swin, self.stcpb, self.dtcpb, self.dwin, 0.05592,
                   self.synack, self.ackdat, 139.5286, 116.2750, self.trans_depth,
                   1595.37188, self.ct_srv_src, 1.3692, self.ct_dst_ltm,
                   self.ct_src_dport_ltm, self.ct_dst_sport_ltm,self.ct_dst_src_ltm,
                   self.is_ftp_login, self.ct_ftp_cmd, self.ct_flw_http_mthd,
                   self.ct_src_ltm, self.ct_srv_dst, self.is_sm_ips_ports,
                   self.srcip, self.dstip, self.start_time, self.lable, self.attack_cat]
            writer.writerow(row)

    def in_features(self):
        row = [[self.dur, self.proto, self.service, 1.8620, self.Spkts, self.Dpkts,
               self.sbytes, self.dbytes, 82410.88, self.sttl, self.dttl, self.Sload,
               self.Dload, 4.7536, 6.3085, self.Sintpkt, self.Dintpkt, 6363.0750,
               535.18043, self.swin, self.stcpb, self.dtcpb, self.dwin, 0.05592,
               self.synack, self.ackdat, 139.5286, 116.2750, self.trans_depth,
               1595.37188, self.ct_srv_src, 1.3692, self.ct_dst_ltm,
               self.ct_src_dport_ltm, self.ct_dst_sport_ltm, self.ct_dst_src_ltm,
               self.is_ftp_login, self.ct_ftp_cmd, self.ct_flw_http_mthd,
               self.ct_src_ltm, self.ct_srv_dst, self.is_sm_ips_ports]]
        return row
