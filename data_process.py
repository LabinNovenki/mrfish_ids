import pandas as pd
import numpy as np
import configparser
import torch


def data_processing(csv_file):
    data = pd.read_csv(csv_file)
    max_len = len(data)
    # print(max_len)

    # print("features coding...")
    # data_atk = pd.read_csv("set/training_atk.csv")
    conf = configparser.ConfigParser()
    conf.read("config/coding.ini")
    # data.loc[1, 'proto'] = int(conf.get('protocal', data.loc[1, 'proto']))

    # 特征编码
    #     print(data.dtypes)
    for index in range(0, max_len):
        data.loc[index, 'proto'] = int(conf.get('protocal', data.loc[index, 'proto']))
        data.loc[index, 'service'] = int(conf.get('service', data.loc[index, 'service']))
    # print('processing row' + str(index) + '...')

    conf.read("config/settings.ini", encoding='utf-8')
    # 完成数据的归一化
    for each_col in data:
        # print(each_col)
        if each_col == 'id' or each_col == 'Unnamed: 0' \
                or each_col == 'attack_cat' or each_col == 'label' \
                or each_col == 'is_sm_ips_ports' or each_col == \
                'Source' or each_col == 'Destination':
            continue
        max_ = float(conf.get('param', each_col + '_max'))
        min_ = float(conf.get('param', each_col + '_min'))
        # print('processing col:' + each_col + '...\n')
        count = 1

        for i in range(0, max_len):
            data.loc[i, each_col] = (data.loc[i, each_col] - min_) / (max_ - min_)
    data.to_csv("logs/records.csv", index=None)


def connection_processing(connection):
    conf = configparser.ConfigParser()
    conf.read("config/coding.ini")

    # 特征编码
    connection[0][1] = int(conf.get('protocal', connection[0][1]))
    if connection[0][2] != '-':
        connection[0][2] = int(conf.get('service', connection[0][1]))
    else:
        connection[0][2] = 999
    # print('processing row' + str(index) + '...')
    conf.read("config/settings.ini", encoding='utf-8')
    # 完成数据的归一化
    param = [(59.999989, 0.0), (132, 2), (999, 2), (7, 1), (10646, 1), (11018, 0),
             (14355774, 24), (14657531, 0),(1000000.003, 0.0),
             (255, 0), (253, 0), (5268000256.0, 0.0), (20821108.0, 0.0), (5319, 0),
             (5507, 0), (60009.992, 0.0), (57739.24, 0.0), (1483830.917, 0.0),
             (463199.2401, 0.0), (255, 0),(4294949667, 0),
             (4294880717, 0), (255, 0), (3.821465, 0.0), (3.226788, 0.0),
             (2.928778, 0.0), (1504, 24), (1500, 0),
             (131, 0), (5242880, 0), (63, 1), (6, 0),(59, 1), (59, 1), (38, 1),
             (63, 1), (2, 0), (2, 0), (16, 0),
             (60, 1), (62, 1), (1, 0), (9, 0), (1, 0)]
    for i in range(len(connection[0])):
        max_ = param[i][0]
        min_ = param[i][1]
        # print('processing col:' + each_col + '...\n')
        connection[0][i] = (connection[0][i] - min_) / (max_ - min_)
    return connection


# 将numpy数组转换为形状为(1, 6, 7)的张量
def data_trans_cnn(X):
    X = np.array(X).astype(np.float64)
    x = []
    for each in X:
        each = each.reshape(1, 6, 7)
        x.append(each)
    # print(x)
    x = np.array(x).astype(np.float64)
    x = torch.from_numpy(x).type(torch.FloatTensor)
    return x


def data_trans_rnn(X):
    X = np.array(X).astype(np.float64)
    X = X.reshape(X.shape[0], 1, X.shape[1])
    X = torch.from_numpy(X).type(torch.FloatTensor)
    return X


def data_trans_nn(X):
    X = np.array(X).astype(np.float64)
    X = torch.from_numpy(X).type(torch.FloatTensor)
    return X


def read_data(csv_file, mod):
    records_df = pd.read_csv(csv_file)
    records_list = records_df.values
    records_split = records_list[:, 1:43]
    records_trans = None
    if mod.lower() == 'cnn':
        records_trans = data_trans_cnn(records_split, 1, 6, 7)
    elif mod.lower() == 'nn':
        records_split = np.array(records_split).astype(np.float64)
        records_trans = torch.from_numpy(records_split).type(torch.FloatTensor)
    elif mod.lower() == 'rnn':
        records_trans = data_trans_rnn(records_split)
    return records_trans


'''
for each_col in data:
    max_ = data[each_col].max()
    min_ = min(data[each_col])
    mean_ = data[each_col].mean()
    print(each_col + '_max=' + str(max_) + + '\n' + each_col + '_min=', str(min_))
'''
# data_processing("logs/log_con.csv")
