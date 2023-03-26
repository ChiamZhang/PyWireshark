import tkinter as tk

from windows import helpWindwos

root = tk.Tk()
root.title('tkinter模拟表格')

table = []
row = []  # row里面加满一行的就添加到上面的table里，使table成为一个二维列表。

for r in range(4):
    for c in range(3):
        widget = tk.Button(root)
        widget.grid(row=r, column=c)
        row.append(widget)  # 把每次创建的Entry对象添加到row列表里
    table.append(row)  # 把row列表添加到table列表里，使table成为一个二维列表。

##加个表头试一下
field = ['姓名', '性别', '年龄']
for t in field:
    table[0][field.index(t)].config(
        textvariable=tk.StringVar(value="123"),
        justify='center',
        state='disable',  # 不让改动可加这个参数，normal是可改动
        command=helpWindwos.showInstructions,
    )


root.mainloop()