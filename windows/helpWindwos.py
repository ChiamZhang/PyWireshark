import tkinter as tk
def showInstructions():
    instructionsWindow = tk.Tk()
    instructionsWindow.title("使用说明")
    instructionsWindow.geometry('1024x720')
    instructionsText=["使用说明\n"
                      +"本项目基于scapy完成，能够按照网卡通过BPF表达式完成抓包，并且能够判断BPF表达式的正确性\n"
                      +"步骤1：首先选择网卡，不选择默认为抓取所有网卡的数据包\n"
                      +"步骤2：使用BPF表达式进行过滤，不填写为不使用\n"
                      +"步骤3：停止抓包后会显示包列表，点击即可查看详细信息\n"
                      +"步骤4：如果对于某个包TCP流感兴趣可以点击流追踪，即可完成IP+Port的流追踪功能。\n"
                      ]
    instructionsBox = tk.Text(instructionsWindow, wrap="none", heigh=100)
    instructionsBox.pack(side="top",fill='x')
    for line in instructionsText:
        instructionsBox.insert("end",line)
        instructionsBox.insert("end", "\n")
    instructionsWindow.mainloop()
