# -*- coding: utf-8 -*-
from scapy.all import *
import datetime
import time
import threading


def realtime_sniff():
    global flag  # 公共变量用于多线程中的”锁“
    while flag:
        # 设置过滤规则，端口号为53，且为udp数据包
        _packet = sniff(store=1, filter='port 53 && udp', timeout=20)  # 每20秒保存一个
        time_now = datetime.datetime.now()
        # 保存为pcap文件 命名为当前时间
        wrpcap("../RealTimePacket/" + datetime.datetime.strftime(time_now,
                                    '%Y-%m-%d-%H-%M-%S') + '.pcap', _packet)


def get_file():
    global flag  # 公共变量用于多线程中的”锁“
    while flag:
        for root, dirs, files in os.walk("../RealTimePacket/"):
            for f in files:
                file_time_str = os.path.join(f)[:19]
                try:
                    # 获取文件时间，判断是否过期
                    file_time = datetime.datetime.strptime(file_time_str, '%Y-%m-%d-%H-%M-%S')
                except:
                    file_time = datetime.datetime.now()
                    os.remove(os.path.join(root, f))        # 如果数据包命名不合法，删除此数据包
                now_time = datetime.datetime.now()
                if (now_time - file_time).seconds > 3600:   # 如果数据包时间大于1小时，删除此数据包
                    os.remove(os.path.join(root, f))
                print(file_time_str)
        time.sleep(15)


def cmd_exit():
    global flag  # 公共变量用于多线程中的”锁“
    while True:
        cmd = input()
        if cmd == 'exit':
            flag = False
            break
        else:
            continue


if __name__ == '__main__':

    flag = True
    t_realtime_sniff = threading.Thread(target=realtime_sniff)
    t_get_file = threading.Thread(target=get_file)
    t_cmd_exit = threading.Thread(target=cmd_exit)
    t_realtime_sniff.start()
    t_get_file.start()
    t_cmd_exit.start()

    t_cmd_exit.join()
    t_get_file.join()
    t_realtime_sniff.join()

    print("end")




