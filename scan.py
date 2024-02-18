#! /usr/bin/python
# -*-coding: UTF-8 -*-
import socket
from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP, ICMP
import argparse
from threading import Thread
import sys





def tcp_half(ip, port):
    # 创建一个 TCP SYN 数据包
    packet1 = IP(dst=ip) / TCP(dport=port, flags="S")
    # 使用 sr() 函数发送数据包并等待响应，保存在 ans 和 uans 中
    ans, uans = sr(packet1, timeout=3, verbose=0)

    # 如果没有接收到响应
    if not ans:
        # 输出连接失败的信息
        print("{} {} TCP connection failure".format(ip, port))
    # 如果接收到了响应，且第一个元组的第二个元素（即接收到的响应数据包）包含 TCP 层
    elif ans[0][1].haslayer(TCP):
        # 检查接收到的响应数据包中 TCP 层的标志位是否为 0x12（SYN-ACK）
        if ans[0][1][TCP].flags == 0x12:
            # 发送 RST 数据包以关闭连接
            send_rst = sr(IP(dst=ip) / TCP(dport=port, flags="R"), timeout=3, verbose=0)
            # 输出连接已打开的信息
            print("{} {} TCP connection is open".format(ip, port))
        else:
            # 输出连接已关闭的信息
            print("{} {} TCP connection is close".format(ip, port))
    else:
        # 输出连接失败的信息
        print("{} {} TCP connection is failure".format(ip, port))

    # 结束函数
    pass


def tcp_all(ip, port):
    # 创建一个 TCP SYN 数据包
    packet2 = IP(dst=ip) / TCP(dport=port, flags="S")
    # 使用 sr() 函数发送数据包并等待响应，保存在 resp2 和 _ 中（_ 用于忽略不需要的返回值）
    resp2, _ = sr(packet2, timeout=3, verbose=0)

    # 如果没有接收到响应
    if not resp2:
        # 输出连接失败的信息
        print("{} {} TCP connection failure".format(ip, port))
    else:
        # 遍历接收到的响应数据包对
        for snd, rcv in resp2:
            # 检查响应数据包中是否包含 TCP 层，并且 TCP 层的标志位是否为 0x12（SYN-ACK）
            if rcv.haslayer(TCP) and rcv[TCP].flags == 0x12:
                # 发送 RST-ACK 数据包以关闭连接
                send_rst = sr(IP(dst=ip) / TCP(dport=port, flags="AR"), timeout=3, verbose=0)
                # 输出连接已打开的信息
                print("{} {} TCP connection is open".format(ip, port))
                break
        else:
            # 输出连接已关闭的信息
            print("{} {} TCP connection is down".format(ip, port))

    # 结束函数
    pass


# sr 函数：
#
# sr 函数用于发送请求并等待多个响应，返回一个元组，其中包含两个列表，一个包含发送的请求数据包，另一个包含接收到的响应数据包。
# 可以通过遍历返回的元组来处理每个响应。
# sr1 函数：
#
# sr1 函数用于发送请求并等待单个响应，返回一个数据包对象（Packet 类的实例），或者在超时情况下返回 None。


# 这个函数更适用于单一响应的情况，无需处理元组的解包问题。
# 在你的情况下，当你使用 sr 函数时，由于只发送一个 ICMP 请求，而 sr 函数会返回一个元组，其中的响应数据包在 ans[0] 中，
# 但你可能预期的是在 ans[0] 中找到接收到的响应，这导致了解包问题。因此，针对 ICMP 扫描，你应该使用 sr1 函数，因为它更适合单一响应的情况，并且能够避免解包问题。
def icmp_scan(ip, port):
    # 使用 sr1 函数发送 ICMP 请求包并等待响应，超时时间为2秒
    resp3 = sr1(IP(dst=ip) / ICMP(), timeout=2, verbose=0)

    # 如果没有收到响应包，说明 ICMP 连接失败
    if not resp3:
        print("{} {} ICMP connection is down".format(ip, port))
    else:
        # 如果收到了响应包，说明 ICMP 连接正常
        for snd, rcv in resp3:
            print("{} {} ICMP connection is alive".format(ip, port))

    # 函数结束
    pass


# 在Python中，通常用下划线
    #     # _
    #     # 来表示一个变量，这个变量在代码中没有特定的使用。在这里，resp4, _
    #     # 的写法是为了强调，我们只对
    #     # resp4
    #     # 变量感兴趣，而对
    #     # resp4
    #     # 之外的内容不关心。实际上，resp4
    #     # 是一个包含了收到的响应数据包的列表（或元组），而
    #     # _
    #     # 表示一个没有具体用途的占位符。
    #     #
    #     # 这种写法在代码中常见，用来表达一种
    #     # "我们接收到了某个值，但在当前的逻辑中不打算使用它"
    #     # 的意图。这样可以避免将一个不需要的值赋给一个无用的变量，从而提高代码的可读性和清晰度。而且不用解包，这个时候解包也是无所谓的
def udp_scan(ip, port):
    # 使用 sr 函数发送 UDP 请求包并等待响应，超时时间为2秒
    resp4, _ = sr(IP(dst=ip) / UDP(dport=port), timeout=2, verbose=0)

    # 如果没有收到响应包，说明 UDP 连接失败
    if not resp4:
        print("{} {} UDP connection is down".format(ip, port))
    else:
        # 如果收到了响应包，说明 UDP 连接正常
        for snd, rcv in resp4:
            print("{} {} UDP connection is open".format(ip, port))

    # 函数结束
    pass


import socket


def banner_scan(ip, port):
    # 创建一个套接字对象
    s = socket.socket()

    try:
        # 设置套接字超时时间为15秒
        s.settimeout(15)

        # 连接到指定的IP和端口
        s.connect((ip, port))

        # 发送一个简单的"hello"字符串
        s.send("hello".encode())

        # 接收服务器返回的banner信息，最多1024字节
        banner = s.recv(1024)

        # 关闭套接字连接
        s.close()

        # 判断是否收到了banner信息
        if banner:
            print("Banner is {}".format(banner))
        else:
            print("Banner cannot be recognized")

    except socket.error as e:
        # 捕获套接字连接错误
        print("Connection error: {}".format(e))
    except socket.timeout:
        # 捕获套接字超时错误
        print("Banner recognition timed out")

    # 函数结束
    pass


def main():
    # 定义命令行参数使用说明
    usage = "python nmap_self.py -i <IP> -p <port> <Scanning method> or python nmap_self.py -i <IP> -p all <Scanning method>"
    # 创建 ArgumentParser 对象，用于解析命令行参数
    parser = argparse.ArgumentParser(description="Network scanning tool")

    # 添加命令行参数 -i 或 --ipaddr，用于指定目标 IP 地址
    parser.add_argument("-i", "--ipaddr", type=str, dest="ipaddress", help="your target ip here")

    # 添加命令行参数 -p 或 --port，用于指定目标端口，可以是单个端口或者是一个范围
    parser.add_argument("-p", "--port", type=str, dest="port", help="your target port here")

    # 创建互斥参数组，用于指定扫描方法。用户只能选择其中一个方法，不能同时选择多个。
    method_group = parser.add_mutually_exclusive_group(required=True)

    # 添加参数 -sT，用于指定进行 TCP 全开扫描
    method_group.add_argument("-sT", action="store_true", help="TCP全开扫描")

    # 添加参数 -sS，用于指定进行 TCP 半开扫描
    method_group.add_argument("-sS", action="store_true", help="TCP半开扫描")

    # 添加参数 -sP，用于指定进行 ICMP ping 主机扫描
    method_group.add_argument("-sP", action="store_true", help="ICMP ping 主机扫描")

    # 添加参数 -sU，用于指定进行 UDP 扫描
    method_group.add_argument("-sU", action="store_true", help="UDP扫描")

    # 添加参数 -sB，用于指定进行 banner 探测
    method_group.add_argument("-sB", action="store_true", help="banner探测")

    # 解析命令行参数，并将解析结果存储在 args 变量中
    args = parser.parse_args()

    # 获取目标 IP 地址和端口信息
    ip = args.ipaddress
    port = args.port
    #action = "store_true"
    #用于在命令行中表示一个开关选项是否被选中。那么解析器将会将 args.sT 设置为 True，表示用户选择了 TCP 全开扫描。

    if port is None:
        print("Error: Port parameter not provided.")
        return



    # python nmap_self.py -i <ip> -p 81,82 -sT
    elif ',' in port and args.sT:
        #将端口拆分为一个列表
        port = port.split(',')
        a = []
        for i in port:
            a.append(int(i))
        #对于每个指定的端口，使用线程来执行tcp_all函数
        for x in a:
            x = int(x)
            t4 = Thread(target=tcp_all, args=(ip, x))
            t4.start()

    # python nmap_self.py -i <ip> -p 81-85 -sT
    elif '-' in port and args.sT:
        #讲端口拆分为起始值和结束值
        port = port.split('-')
        s = int(port[0])
        d = int(port[1])
        # 遍历端口范围，启动一个线程来执行 tcp_all 函数
        for x in range(int(s), int(d)):
            x = int(x)
            t = Thread(target=tcp_all, args=(ip, x))
            t.start()
    # python nmap_self.py -i <ip> -p all -sT
    elif 'all' in port and args.sT:
        # 遍历所有可能的端口，启动一个线程来执行 tcp_all 函数
        for x in range(65535):
            x = int(x)
            t = Thread(target=tcp_all, args=(ip, x))
            t.start()


    elif ',' in port and args.sP:

        port = port.split(',')
        a = []
        for i in port:
            a.append(int(i))

        for x in a:
            x = int(x)
            t = Thread(target=icmp_scan, args=(ip,x))
            t.start()

    elif '-' in port and args.sP:
        port = port.split('-')
        s = int(port[0])
        d = int(port[1])

        for x in range(int(s), int(d)):
            x = int(x)
            t = Thread(target=icmp_scan, args=(ip,x))
            t.start()

    elif 'all' in port and args.sP:
        for x in range(65535):
            x = int(x)
            t = Thread(target=icmp_scan, args=(ip,x))
            t.start()

    elif ',' in port and args.sS:
        port = port.split(',')
        a = []
        for i in port:
            a.append(int(i))

        for x in a:
            x = int(x)
            t = Thread(target=tcp_half, args=(ip, x))
            t.start()

    elif '-' in port and args.sS:
        port = port.split('-')
        s = int(port[0])
        d = int(port[1])

        for x in range(int(s), int(d)):
            x = int(x)
            t = Thread(target=tcp_half, args=(ip, x))
            t.start()

    elif 'all' in port and args.sS:
        for x in range(65535):
            x = int(x)
            t = Thread(target=tcp_half, args=(ip, x))
            t.start()


    elif ',' in port and args.sU:
        port = port.split(',')
        a = []
        for i in port:
            a.append(int(i))

        for x in a:
            x = int(x)
            t = Thread(target=udp_scan, args=(ip, x))
            t.start()

    elif '-' in port and args.sU:
        port = port.split('-')
        s = int(port[0])
        d = int(port[1])

        for x in range(int(s), int(d)):
            x = int(x)
            t = Thread(target=udp_scan, args=(ip, x))
            t.start()

    elif 'all' in port and args.sU:
        for x in range(65535):
            x = int(x)
            t = Thread(target=udp_scan, args=(ip, x))
            t.start()

    # banner
    elif ',' in port and args.sB:

        port = port.split(',')
        a = []
        for i in port:
            a.append(int(i))

        for x in a:
            x = int(x)
            t = Thread(target=banner_scan, args=(ip, x))
            t.start()

    elif '-' in port and args.sB:

        port = port.split('-')
        s = int(port[0])
        d = int(port[1])

        for x in range(int(s), int(d)):
            x = int(x)
            t = Thread(target=banner_scan, args=(ip, x))
            t.start()

    elif 'all' in port and args.sB:

        for x in range(65535):
            x = int(x)
            t = Thread(target=banner_scan, args=(ip, x))
            t.start()

    else:
        print("error 用法请看工具帮助手册")

    pass


if __name__ == '__main__':
    main()
