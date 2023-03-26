import time
from PySide6 import QtCore
from queue import Queue
from tkinter import *
from tkinter.messagebox import showinfo
from scapy.all import IP
from scapy.all import TCP
from scapy.all import *
import tkinter as tk
from tkinter import messagebox
from io import StringIO
from contextlib import redirect_stdout

from scapy.arch.common import compile_filter

from util.sniff import get_packet_layers
from windows import adapterInformation
from windows import helpWindwos
from windows import zhuizong
# 捕获的数据包的结果会写在下面这个列表中
from util import getAdapterName

my_packages = []
queue = Queue()
sniffer = None
detialWindow = None

def sniff_action(packet):
    if not sniffer:
        return
    queue.put(packet)

def sniff_action(packet):
    queue.put(packet)

def start():
    var1 = variable.get()

    try:
        compile_filter(BPF_Filter.get())
    except:
        tk.messagebox.showerror(title='错误', message='BPF表达式不正确！')

    try:
        global sniffer
        if var1=="默认全部网卡":
            sniffer = AsyncSniffer(prn=sniff_action, filter=BPF_Filter.get())

        else :sniffer = AsyncSniffer(iface=var1, prn=sniff_action, filter=BPF_Filter.get())
        b_1 = tk.Button(window, text='正在抓包', width=15, height=1, command=start).place(x=50, y=5)
        sniffer.start()
        listbox1.delete(0, END)
    except :
        tk.messagebox.showerror(title='错误', message='启动失败')


def end():
    try:
        sniffer.stop()
        b_1 = tk.Button(window, text='开始抓包', width=15, height=1, command=start).place(x=50, y=5)
        cnt=0
        while(queue.qsize()>0):
            packet = queue.get(False)


            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
            else:
                src = packet.src
                dst = packet.dst
            print(src)
            print(dst)
            layer = None
            for var in get_packet_layers(packet):
                if not isinstance(var, (Padding, Raw)):
                    layer = var

            protocol = layer.name
            print(protocol)
            no=str(cnt)+(8-len(str(cnt)))*2*" "
            src=str(src)+(30-len(str(src)))*2*" "
            dst=str(dst)+(30-len(str(dst)))*2*" "
            protocol=str(protocol)+(20-len(str(protocol)))*2*" "
            cnt+=1
            listbox1.insert("end", "{}|    {}|    {}|    {}|    {}\n".format(no,src,dst,protocol, packet.summary()))
            my_packages.append(packet)
    except :
        print("不能正常停止")

def list_select(evt):

    if len(listbox1.curselection())==0:return
    cur = listbox1.curselection()[0]
    if cur is None:
        return
    # print(cur)
    # 获取想要具体查询的包序号
    var3 = int(cur + 1)
    global detialWindow
    # 创建第二个窗口

    detialWindow = tk.Tk()
    detialWindow.title("第{}个包的详细信息".format(var3))
    detialWindow.geometry('800x350')

    scrollbar = tk.Scrollbar(detialWindow)
    scrollbar.pack(side="right", fill="y")
    t1 = tk.Text(detialWindow, wrap="none", width=100, yscrollcommand=scrollbar.set)
    t1.pack(side='top')
    scrollbar.config(command=t1.yview)
    try:

        output_str = StringIO()
        with redirect_stdout(output_str):
            my_packages[var3 - 1].show()

        packageDetail = output_str.getvalue()
        t1.insert("end", packageDetail)
    except:
        tk.messagebox.showerror(title='错误', message='包序号出错！')
    detialWindow.mainloop()



def  follow_stream():
    def list_follow(evt):
        if len(listbox2.curselection()) == 0: return
        cur = listbox2.curselection()[0]
        if cur is None:
            return
        # print(cur)
        # 获取想要具体查询的包序号
        var3 = int(cur + 1)
        global detialWindow
        # 创建第二个窗口

        detialWindow = tk.Tk()
        detialWindow.title("第{}个包的详细信息".format(var3))
        detialWindow.geometry('800x350')

        scrollbar = tk.Scrollbar(detialWindow)
        scrollbar.pack(side="right", fill="y")
        t1 = tk.Text(detialWindow, wrap="none", width=100, yscrollcommand=scrollbar.set)
        t1.pack(side='top')
        scrollbar.config(command=t1.yview)
        try:

            output_str = StringIO()
            with redirect_stdout(output_str):
                my_packages[var3 - 1].show()

            packageDetail = output_str.getvalue()
            t1.insert("end", packageDetail)
        except:
            tk.messagebox.showerror(title='错误', message='包序号出错！')
        detialWindow.mainloop()
    if len(listbox1.curselection())==0:return
    cur = listbox1.curselection()[0]
    if cur is None:
        return
    var3 = int(cur + 1)
    print(var3)
    global detialWindow
    # 创建第二个窗口
    detialWindow = tk.Tk()
    detialWindow.title("流追踪")
    detialWindow.geometry('1024x720')

    listbox2 = tk.Listbox(detialWindow, width=130, height=55, yscrollcommand=yscrollbar.set, xscrollcommand=xscrollbar.set)
    listbox2.bind("<<ListboxSelect>>", list_follow)
    listbox2.pack(side="bottom", fill="x")
    cnt=0
    packetD=my_packages[var3]
    if IP in packetD:
        srcD = packetD[IP].src
        dstD = packetD[IP].dst
    else:
        srcD = packetD.src
        dstD = packetD.dst

    for packet in my_packages:
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
        else:
            src = packet.src
            dst = packet.dst
        print(srcD+" "+dstD)
        if srcD == src and dstD==dst:
            if TCP in packetD and TCP in packet:
                if packetD[TCP].sport==packet[TCP].sport:
                    pass
        elif srcD == dst and dstD==src:
            if TCP in packetD and TCP in packet:
                if packetD[TCP].dport == packet[TCP].sport:
                    pass
        else: continue
        layer = None
        for var in get_packet_layers(packet):
            if not isinstance(var, (Padding, Raw)):
                layer = var

        protocol = layer.name
        print(protocol)
        no=str(cnt)+(8-len(str(cnt)))*2*" "
        src=str(src)+(30-len(str(src)))*2*" "
        dst=str(dst)+(30-len(str(dst)))*2*" "
        protocol=str(protocol)+(20-len(str(protocol)))*2*" "
        cnt+=1
        listbox2.insert("end", "{}|    {}|    {}|    {}|    {}\n".format(no,src,dst,protocol, packet.summary()))




# 创建tkinter主窗口
window = tk.Tk()
window.title('PyWireshark')
window.geometry('1024x720')


tip1 = tk.Label(window, text='网卡选择：')   # 创建一个标签
tip1.place(x=50, y=45)                    # 确定标签位置

var1 = tk.StringVar()
adpName=getAdapterName.get_adapter_name()
variable = tk.StringVar(window)
variable.set('默认全部网卡')
opt = tk.OptionMenu(window, variable, *adpName)
opt.config(width=30,)
opt.place(x=110, y=40)


tip4 = tk.Label(window, text='BPF过滤：')
tip4.place(x=370,y=45)
BPF_Filter = tk.Entry(window, show=None,width=78)
BPF_Filter.place(x=445,y=45)
var3 = tk.StringVar()

b_1 = tk.Button(window, text='开始抓包', width=15, height=1,command=start).place(x=50, y=5)
b_5 = tk.Button(window, text='停止抓包', width=15, height=1,command=end).place(x=150,y=5)
b_4 = tk.Button(window, text='流追踪', width=15, height=1,command=follow_stream).place(x=250,y=5)
b_3 = tk.Button(window, text='帮助说明', width=15, height=1,command=helpWindwos.showInstructions).place(x=450,y=5)
b_6 = tk.Button(window, text='网卡信息', width=15, height=1,command=adapterInformation.showInformation).place(x=350,y=5)

yscrollbar = tk.Scrollbar(window)
yscrollbar.pack(side="right", fill="y")
xscrollbar = tk.Scrollbar(window,orient="horizontal")
xscrollbar.pack(side="bottom", fill="x")

listbox1= tk.Listbox( window,width=130, height=33,yscrollcommand=yscrollbar.set, xscrollcommand=xscrollbar.set)
listbox1.bind("<<ListboxSelect>>",list_select)
# listbox1.place(x=50, y=110)
listbox1.pack(side="bottom", fill="x")


yscrollbar.config(command=listbox1.yview)
xscrollbar.config(command=listbox1.xview)

window.mainloop()



