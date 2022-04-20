# -*- coding: utf-8 -*-
import os
import threading
from scapy.all import *
from PcapParser import PcapParser


def realtime_sniff():
    global flag
    while flag:
        _packet = sniff(store=1, filter='port 53', timeout=20)  # 每20秒保存一个
        time_now = datetime.now()
        # 保存为pcap文件
        wrpcap("../RealTimePacket/" + datetime.strftime(time_now, '%Y-%m-%d-%H-%M-%S') + '.pcap', _packet)


def get_file():
    global flag
    i = 1
    while flag:
        for root, dirs, files in os.walk("../RealTimePacket/"):
            for f in files:
                file_time_str = os.path.join(f)[:19]
                try:
                    file_time = datetime.strptime(file_time_str, '%Y-%m-%d-%H-%M-%S')
                except:
                    file_time = datetime.now()
                    os.remove(os.path.join(root, f))
                now_time = datetime.now()
                if (now_time - file_time).seconds > 36000:
                    os.remove(os.path.join(root, f))
        time.sleep(19)
        print("已经检测%d秒..." % (i * 20))
        i += 1


def cmd_exit():
    global flag
    while True:
        cmd = input()
        if cmd == 'exit':
            flag = False
            break
        else:
            continue


def realtime_detect():
    global flag
    while flag:
        try:
            fn_in = "../Output/DNS_FP.csv"
            fn_out = "../Output/DNS_FP_RESULT.csv"
            if os.path.exists(fn_in):
                os.remove(fn_in)
            if os.path.exists(fn_out):
                os.remove(fn_out)
            _folder = "../RealTimePacket/"
            _filename = "dns_realtime_traffic.pcap"
            _obj_dns_parser = PcapParser(10000000, 3, _folder, _filename, 1, 1)
            _obj_dns_parser.start_parse()
            time.sleep(10)
        except Exception as _e:
            print(_e)


if __name__ == '__main__':
    # pcaplist = ['20160421_150521.pcap']
    # pcaplist1 = ['dns2tcp.pcap']
    # pcaplist2 = ['dns2tcp.pcap', 'dns2tcp_02.pcap']
    # pcaplist3 = ["dnscat_01.pcap"]

    print("========= Welcome to Bot Network Detector =========")
    print("||           Update Time : 2020-12-3             ||")
    print("||           Version     : 1.0                   ||")
    print("======Program Started at " + datetime.strftime(datetime.now(),
                                                                   '%Y-%m-%d  %H:%M:%S') + "======")

    while True:
        print("[cmd]\n[1]实时流量监控\n[2]pcap文件检测\n[3]退出系统")
        cmd_init = input("请输入命令(1-3的某个整数): ")
        if cmd_init.isdigit():
            if int(cmd_init) == 1:
                print("正在进行实时dns流量检测(输入exit退出)...")

                flag = True
                t_realtime_sniff = threading.Thread(target=realtime_sniff)
                t_get_file = threading.Thread(target=get_file)
                t_cmd_exit = threading.Thread(target=cmd_exit)
                t_realtime_detect = threading.Thread(target=realtime_detect)
                t_realtime_sniff.start()
                t_get_file.start()
                t_cmd_exit.start()
                t_realtime_detect.start()

                t_cmd_exit.join()
                t_realtime_detect.join()
                t_get_file.join()
                t_realtime_sniff.join()
                continue
            elif int(cmd_init) == 2:
                print("请将待扫描的pcap文件放入文件夹InputFile内(支持多个)")
                cmd_infile = input("确认放入后请输入1")
                if int(cmd_infile) == 1:
                    try:
                        folder = "../InputFile/"
                        filename = "dns_traffic.pcap"
                        obj_dns_parser = PcapParser(10000000, 3, folder, filename, 1, 2)
                        obj_dns_parser.start_parse()
                    except Exception as e:
                        print(e)
                continue
            elif int(cmd_init) == 3:
                input("\n欢迎下次使用，bye-bye！")
                exit(0)
                break
        print("[命令错误]请重新输入，请输入1-3的某个整数")

    input("\n欢迎下次使用，bye-bye！")
    exit(0)
