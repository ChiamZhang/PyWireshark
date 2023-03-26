import time
from concurrent.futures import thread
from multiprocessing import Process
import threading
from PySide6 import QtCore
from queue import Queue
from tkinter import *
from tkinter.messagebox import showinfo
from scapy.all import IP
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
import os

my_packages = []
queue = Queue()
sniffer = None
detialWindow = None
cnt = 0
stopFlag = False
b_1=None
list_box=[]
text_box=[]

def sniff_action(packet):
    global queue

    if not sniffer:
        return
    queue.put(packet)


def start():
    var1 = variable.get()

    try:
        compile_filter(BPF_Filter.get())
    except:
        tk.messagebox.showerror(title='错误', message='BPF表达式不正确！')

    try:

        global sniffer

        if var1 == "默认全部网卡":
            sniffer = AsyncSniffer(prn=sniff_action, filter=BPF_Filter.get())

        else:
            sniffer = AsyncSniffer(iface=var1, prn=sniff_action, filter=BPF_Filter.get())
        global cnt, stopFlag
        cnt = 0
        stopFlag = False
        sniffer.start()
        global b_1
        b_1=tk.Button(window, text='正在抓包', width=15, height=1, command=start,state='disable').place(x=50, y=5)


    except Exception as E:
        tk.messagebox.showerror(title='错误', message='启动失败')
        print(E)


def showData():
    global cnt, stopFlag, queue,list_box

    while (queue.qsize() > 0):

        packet = queue.get(False)

        # for i in range(eval(var2)):
        #
        #     packet = packages[i]
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
        else:
            src = packet.src
            dst = packet.dst
        # print(src)
        # print(dst)
        layer = None
        for var in get_packet_layers(packet):
            if not isinstance(var, (Padding, Raw)):
                layer = var

        protocol = layer.name
        # print(protocol)
        print(packet.summary())
        cnt += 1
        listbox1.insert(str(cnt))
        listbox2.insert(cnt, str(src))
        # listbox2.insert(str(src))
        listbox3.insert(cnt, str(dst))
        listbox4.insert(cnt, str(protocol))
        listbox4.insert(cnt, f"{len(packet)}")
        # listbox5.insert( f"{len(packet)}")
        # listbox6.insert(str(packet.summary()))
        listbox6.insert(cnt, str(packet.summary()))
        my_packages.append(packet)


def end():
    sniffer.stop()
    b_1 = tk.Button(window, text='开始抓包', width=15, height=1, command=start).place(x=50, y=5)

    time.sleep(1)
    showData()
    # try:
    #     sniffer.stop()
    #     b_1=tk.Button(window, text='开始抓包', width=15, height=1, command=start).place(x=50, y=5)
    #
    #     time.sleep(1)
    #     showData()
    #
    # except Exception as E:
    #     tk.messagebox.showerror(title='错误', message='没有开始扫描！')
    #     print(E)

def list_select(evt):
    if len(listbox1.curselection()) == 0:
        return

    cur = listbox1.curselection()[0]
    if cur is None:
        return

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



# 创建tkinter主窗口
window = tk.Tk()
window.title('PyWireshark')
window.geometry('1024x720')

tip1 = tk.Label(window, text='网卡选择：')  # 创建一个标签
tip1.place(x=50, y=45)  # 确定标签位置

var1 = tk.StringVar()
adpName = getAdapterName.get_adapter_name()
variable = tk.StringVar(window)
variable.set('默认全部网卡')
opt = tk.OptionMenu(window, variable, *adpName)
opt.config(width=30, )
opt.place(x=110, y=40)

tip4 = tk.Label(window, text='BPF过滤：')
tip4.place(x=370, y=45)
BPF_Filter = tk.Entry(window, show=None, width=78)
BPF_Filter.place(x=445, y=45)
var3 = tk.StringVar()

b_1 = tk.Button(window, text='开始抓包', width=15, height=1, command=start).place(x=50, y=5)
b_5 = tk.Button(window, text='停止抓包', width=15, height=1, command=end).place(x=150, y=5)
b_4 = tk.Button(window, text='流追踪', width=15, height=1, command=zhuizong.model2).place(x=250, y=5)
b_3 = tk.Button(window, text='帮助说明', width=15, height=1, command=helpWindwos.showInstructions).place(x=450, y=5)
b_6 = tk.Button(window, text='网卡信息', width=15, height=1, command=adapterInformation.showInformation).place(x=350, y=5)


yscrollbar = tk.Scrollbar(window)
yscrollbar.pack(side="right", fill="y")
xscrollbar = tk.Scrollbar(window, orient="horizontal")
xscrollbar.pack(side="bottom", fill="x")


text_word=["No.","Source","Destinatior","Protocol","Length","Info"]

i=0
listbox1 = tk.Listbox(window, width=10, height=30, yscrollcommand=yscrollbar.set, xscrollcommand=xscrollbar.set)
listbox1.bind("<<ListboxSelect>>", list_select)
listbox1.place(x=50+i*70, y=110)
list_box.append(listbox1)
tip1 = tk.Label(window, text=text_word[i])  # 创建一个标签
tip1.place(x=50+i*70+5, y=88)  # 确定标签位置
text_box.append(tip1)
i+=1
listbox2 = tk.Listbox(window, width=10, height=30, yscrollcommand=yscrollbar.set, xscrollcommand=xscrollbar.set)
listbox2.bind("<<ListboxSelect>>", list_select)
listbox2.place(x=50+i*70, y=110)
list_box.append(listbox2)
tip2 = tk.Label(window, text=text_word[i])  # 创建一个标签
tip2.place(x=50+i*70+5, y=88)  # 确定标签位置
text_box.append(tip2)
i+=1
listbox3 = tk.Listbox(window, width=10, height=30, yscrollcommand=yscrollbar.set, xscrollcommand=xscrollbar.set)
listbox3.bind("<<ListboxSelect>>", list_select)
listbox3.place(x=50+i*70, y=110)
list_box.append(listbox3)
tip3 = tk.Label(window, text=text_word[i])  # 创建一个标签
tip3.place(x=50+i*70+5, y=88)  # 确定标签位置
text_box.append(tip3)
i+=1
listbox4 = tk.Listbox(window, width=10, height=30, yscrollcommand=yscrollbar.set, xscrollcommand=xscrollbar.set)
listbox4.bind("<<ListboxSelect>>", list_select)
listbox4.place(x=50+i*70, y=110)
list_box.append(listbox4)
tip4 = tk.Label(window, text=text_word[i])  # 创建一个标签
tip4.place(x=50+i*70+5, y=88)  # 确定标签位置
text_box.append(tip4)
i+=1
listbox5 = tk.Listbox(window, width=10, height=30, yscrollcommand=yscrollbar.set, xscrollcommand=xscrollbar.set)
listbox5.bind("<<ListboxSelect>>", list_select)
listbox5.place(x=50+i*70, y=110)
list_box.append(listbox5)
tip5 = tk.Label(window, text=text_word[i])  # 创建一个标签
tip5.place(x=50+i*70+5, y=88)  # 确定标签位置
text_box.append(tip5)

listbox6 = tk.Listbox(window, width=80, height=30, yscrollcommand=yscrollbar.set, xscrollcommand=xscrollbar.set)
listbox6.bind("<<ListboxSelect>>", list_select)
listbox6.place(x=50+5*70, y=110)
list_box.append(listbox6)
tip6 = tk.Label(window, text=text_word[5])  # 创建一个标签
tip1.place(x=50 + 6 * 70+5, y=88)  # 确定标签位置
text_box.append(tip6)



yscrollbar.config(command=listbox1.yview)
xscrollbar.config(command=listbox1.xview)

table = []
row = []  # row里面加满一行的就添加到上面的table里，使table成为一个二维列表。

window.mainloop()
# Todo
# 后面删除所有的注释后的代码
