import prettytable as pt
import pandas as pd


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


def input_dealing(str):
    ret = ''
    # print('get command:', str)
    if str == 'show log':
        ret = 'Unrecognized command.\nmay be you want to write command as follows:\n' \
              '1.show pkt log\n2.show con log'
    elif str == 'show pkt log':
        ret = print_log_pkt()
    elif str == 'show con log':
        ret = print_log_con()
    elif str == 'quit' or str == 'exit':
        exit(0)
    else:
        ret = 'Unrecognized command.\nPlease check your command input, or click ' \
              'help for more information'
    return ret