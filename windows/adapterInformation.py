import tkinter as tk
from util import getAdapterName
def showInformation():
    showInformationWindow = tk.Tk()
    showInformationWindow.title("网卡信息")
    showInformationWindow.geometry('1024x720')
    showInformationText=getAdapterName.get_adapter_information()
    showInformationBox = tk.Text(showInformationWindow, wrap="none", heigh=100)
    showInformationBox.pack(fill='x')
    for line in showInformationText:
        showInformationBox.insert("end",line)
        # showInformationBox.insert("end", "\n")
    showInformationWindow.mainloop()
