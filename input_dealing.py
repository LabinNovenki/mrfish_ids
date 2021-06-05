import prettytable as pt
import pandas as pd
import configparser as cp
import re

def print_log_pkt():
    try:
        df = pd.read_csv('logs/log_pkt.csv')
    except:
        ret = 'Can\'t find the file \'log_pkt.csv\'.\nThe Local log file might be ' \
               'modified or deleted.\nPlease check file integrity.'
        return ret
    df_v = df.values
    table = pt.PrettyTable()
    table.field_names = ["id", "Time", "Source", "Destination", "Sport", "Dport", "Protocal"]
    for eachline in df_v:
        table.add_row(eachline)
    return str(table)


def print_log_con():
    try:
        df = pd.read_csv('logs/log_con.csv')
    except:
        ret = 'Can\'t find the file \'log_con.csv\'.\nThe Local log file might be ' \
               'modified or deleted.\nPlease check file integrity.'
        return ret
    df_v = df.values
    table = pt.PrettyTable()
    table.field_names = ["id", "Time", "Dur", "Source", "Destination", "Protocal", "spkts", "dpkts"]
    for eachline in df_v:
        row = [eachline[0], eachline[45], eachline[1], eachline[43], eachline[44],
               eachline[2], eachline[5], eachline[6]]
        table.add_row(row)
    return str(table)


def input_dealing(string):
    ret = ''
    # print(string)
    string = string.lower()
    conf = cp.ConfigParser()
    conf.read('config/settings.ini', encoding='utf-8')
    # print('get command:', str)
    if string == 'show log':
        ret = 'Unrecognized command.\nmay be you want to write command as follows:\n' \
              '1.show pkt log\n2.show con log'
    elif string == 'show pkt log':
        ret = print_log_pkt()
    elif string == 'show con log':
        ret = print_log_con()
    elif string == 'set mod cnn':
        conf.set('sniffer', 'MOD', '1')
        conf.write(open('config/settings.ini', "w"))
        ret = 'the setting has been modified.'
    elif string == 'set mod nn':
        conf.set('sniffer', 'MOD', '2')
        conf.write(open('config/settings.ini', "w"))
        ret = 'the setting has been modified.'
    elif string == 'set mod rnn':
        conf.set('sniffer', 'MOD', '3')
        conf.write(open('config/settings.ini', "w"))
        ret = 'the setting has been modified.'
    elif string == 'clear on':
        conf.set('sniffer', 'CLEAR', '1')
        conf.write(open('config/settings.ini', "w"))
        ret = 'the setting has been modified.'
    elif string == 'clear off':
        conf.set('sniffer', 'CLEAR', '0')
        conf.write(open('config/settings.ini', "w"))
        ret = 'the setting has been modified.'
    elif string == 'update on':
        conf.set('sniffer', 'UPDATE', '1')
        conf.write(open('config/settings.ini', "w"))
        ret = 'the setting has been modified.'
    elif string == 'update off':
        conf.set('sniffer', 'UPDATE', '0')
        conf.write(open('config/settings.ini', "w"))
        ret = 'the setting has been modified.'
    elif string == 'classify on':
        conf.set('sniffer', 'CLASSIFIER', '1')
        conf.write(open('config/settings.ini', "w"))
        ret = 'the setting has been modified.'
    elif string == 'classify off':
        conf.set('sniffer', 'CLASSIFIER', '0')
        conf.write(open('config/settings.ini', "w"))
        ret = 'the setting has been modified.'
    elif string == 'quit' or string == 'exit':
        exit(0)
    else:
        ret = 'Unrecognized command.\nPlease check your command input, or click ' \
              'help for more information'
    return ret