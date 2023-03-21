import tkinter as tk
def showInstructions():
    instructionsWindow = tk.Tk()
    instructionsWindow.title("使用说明")
    instructionsWindow.geometry('1024x720')
    instructionsText=["使用说明。。。。。。。项目完成再补"]
    instructionsBox = tk.Text(instructionsWindow, wrap="none", heigh=100)
    instructionsBox.pack(side="top",fill='x')
    for line in instructionsText:
        instructionsBox.insert("end",line)
        instructionsBox.insert("end", "\n")
    instructionsWindow.mainloop()
