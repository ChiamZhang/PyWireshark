import threading
import tkinter as tk
import os
import socket
import datetime as dt
from entity import IP_Entity as IP
import time
def model2():
    #此函数为持续监听模式，点击持续监听即可跳转至此界面

    # Windows下嗅探所有数据包，Linux下嗅探ICMP数据包
    def start():
        var = e.get()
        if os.name == "nt":  # 判断系统是否为window
            socket_protocol = socket.IPPROTO_IP  # 设置协议为ip协议
        else:
            socket_protocol = socket.IPPROTO_ICMP
        global sniffer

        # 创建一个原始套接字
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        try:
            sniffer.bind((var, 0))  # 套接字绑定地址，0默认所有端口
        except:
            tk.messagebox.showerror(title='错误', message='socket连接错误')  # 若绑定失败则弹窗解释

        # 设置ip头部
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Windows下要打开混杂模式
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            # 设置开启混杂模式，socket.SIO_RCVALL默认接收所有数据，socket.RCVALL_ON开启
        show_th = threading.Thread(target=show)  # 创建一个线程，执行函数为show()
        show_th.setDaemon(True)
        show_th.start()

    def show():
        window2.title('正在抓包...')  # 更改界面标题
        while True:
            # 读取数据包
            raw_buffer = sniffer.recvfrom(65535)[0]  # 获取数据包，接收最大字节数为65565
            # 读取前20字节
            ip_header = IP.IpEntity(raw_buffer[0:24])
            # 输出协议和双方通信的IP地址
            now_time = dt.datetime.now().strftime('%T')  # 获取系统当前时间
            result = '协议: ' + str(ip_header.protocol) + ' ' + str(ip_header.src_address) + ' : ' + str(
                ip_header.src_port) + ' -> ' + str(ip_header.dst_address) + ' : ' + str(
                ip_header.dst_port) + '  size:' + str(ip_header.len) + ' 时间:' + str(now_time) + '\n'  # 设置输出的字符串
            t.insert('end', result)  # 将每条输出插入到界面
            time.sleep(0.1)

    def stop():
        window2.title('抓包已停止')
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)  # 关闭混杂模式，第一个参数是接收所有数据，第二个对应关闭
        sniffer.close()  # 关闭套接字


    #此处开始，相当于是持续监听模式的主函数
    window2 = tk.Tk()
    window2.title('IP:Port的TCP流追踪')
    window2.geometry('800x600')
    # 本地监听
    l = tk.Label(window2, text='网卡ip：')
    l.place(x=150, y=65)
    e = tk.Entry(window2, show=None)
    e.place(x=250, y=65)
    var = tk.StringVar()  # 定义一个字符串变量
    b_1 = tk.Button(window2, text='开始抓包', width=15, height=2, command=start).place(x=450, y=20)
    b_2 = tk.Button(window2, text='停止抓包', width=15, height=2, command=stop).place(x=450, y=80)
    t = tk.Text(window2, width=100)
    t.place(x=50, y=200)
    window2.mainloop()