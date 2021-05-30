# 连接集，负责管理已完成的连接和统计
import pkt_parse
import csv

class Connection_set:
    def __init__(self):
        self.connections = []
        self.size = 100
        self.count = 0

    def add_connection(self, con:pkt_parse.Connection):
        """
        向连接集中添加已经完成的连接
        :param con: 已完成的连接
        :return:
        """
        self.connections.append(con)
        self.count += 1
        if len(self.connections) > 100:
            self.connections.pop(0)

    def connection_ct_features(self, con:pkt_parse.Connection):
        """
        增添连接的统计特征
        :param con:连接
        :return:
        """
        for connection in self.connections:
            if connection.srcip == con.srcip:
                con.ct_src_ltm += 1
            if connection.dstip == con.dstip:
                con.ct_dst_ltm += 1
            if connection.service == con.service and connection.srcip == con.srcip:
                con.ct_srv_src += 1
            if connection.service == con.service and connection.dstip == con.dstip:
                con.ct_srv_dst += 1
            if connection.srcip == con.srcip and connection.dsport == con.dsport:
                con.ct_src_dport_ltm += 1
            if connection.dstip == con.dstip and connection.sport == con.sport:
                con.ct_dst_sport_ltm += 1
            if connection.dstip == con.dstip and connection.srcip == con.srcip:
                con.ct_dst_src_ltm += 1

    def output(self):
        """
        保留函数，或许需要用来输出统计信息
        :return:
        """
        pass