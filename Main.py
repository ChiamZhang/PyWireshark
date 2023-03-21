from scapy.all import *
import tkinter as tk
from tkinter import messagebox
from io import StringIO
from contextlib import redirect_stdout




from windows import adapterInformation
from windows import helpWindwos
from windows import zhuizong
#捕获的数据包的结果会写在下面这个列表中
from util import getAdapterName


my_packages = []

def start():
    var1 = variable.get()
    var2 = packageCnt.get()
    try:
        if type(eval(var2)) is not int:
            tk.messagebox.showerror(title='错误', message='抓包数量必须为整数！')
            return
    except:
        tk.messagebox.showerror(title='错误', message='抓包数量必须为整数！')
        return
    try:
        packages = sniff(iface=var1, count=eval(var2))
    except:
        tk.messagebox.showerror(title='错误', message='网卡不存在')
        return
    for i in range(eval(var2)):
        t.insert("end", "序号：{}   {}\n".format(i+1,packages[i].summary()))
        my_packages.append(packages[i])



def showDetail():
    #获取想要具体查询的包序号
    var3 = packageNum.get()
    #创建第二个窗口
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
            my_packages[eval(var3)-1].show()
        packageDetail = output_str.getvalue()
        t1.insert("end",packageDetail)
    except:
        tk.messagebox.showerror(title='错误', message='包序号出错！')
    detialWindow.mainloop()








# 创建tkinter主窗口
window = tk.Tk()
window.title('PyWireshark')
window.geometry('1024x720')


tip1 = tk.Label(window, text='网卡名称：')   # 创建一个标签
tip1.place(x=50, y=45)                    # 确定标签位置

var1 = tk.StringVar()
adpName=getAdapterName.get_adapter_name()
variable = tk.StringVar(window)
variable.set('选择网卡')
opt = tk.OptionMenu(window, variable, *adpName)
opt.config(width=30,)
opt.place(x=110, y=40)



tip2 = tk.Label(window, text='抓包数量：')
tip2.place(x=380,y=45)
packageCnt = tk.Entry(window, show=None)
packageCnt.place(x=440, y=45)
var2 = tk.StringVar()

tip3 = tk.Label(window, text='查看序号：')
tip3.place(x=600,y=45)
packageNum = tk.Entry(window, show=None)
packageNum.place(x=660,y=45)
var3 = tk.StringVar()

tip4 = tk.Label(window, text='BPF过滤：')
tip4.place(x=50,y=80)
BPF_Filter = tk.Entry(window, show=None,width=121)
BPF_Filter.place(x=110,y=80)
var3 = tk.StringVar()

b_1 = tk.Button(window, text='开始抓包', width=15, height=1,command=start).place(x=50, y=5)
b_2 = tk.Button(window, text='详细信息', width=15, height=1,command=showDetail).place(x=820,y=40)
b_5 = tk.Button(window, text='停止抓包', width=15, height=1,command=helpWindwos.showInstructions).place(x=150,y=5)
b_4 = tk.Button(window, text='流追踪', width=15, height=1,command=zhuizong.model2).place(x=250,y=5)
b_3 = tk.Button(window, text='帮助说明', width=15, height=1,command=helpWindwos.showInstructions).place(x=450,y=5)
b_6 = tk.Button(window, text='网卡信息', width=15, height=1,command=adapterInformation.showInformation).place(x=350,y=5)

yscrollbar = tk.Scrollbar(window)
yscrollbar.pack(side="right", fill="y")
xscrollbar = tk.Scrollbar(window,orient="horizontal")
xscrollbar.pack(side="bottom", fill="x")
t = tk.Text(window, wrap="none",width=130, height=45,yscrollcommand=yscrollbar.set, xscrollcommand=xscrollbar.set)
t.place(x=50, y=110)
yscrollbar.config(command=t.yview)
xscrollbar.config(command=t.xview)

window.mainloop()
