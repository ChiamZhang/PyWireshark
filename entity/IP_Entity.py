# IP头定义
from ctypes import *


class IP(Structure):
    _fields_ = [
        ('ihl', c_ubyte, 4),
        ('version', c_ubyte, 4),
        ('tos', c_ubyte),
        ('len', c_ushort),
        ('id', c_ushort),
        ('offset', c_ushort),
        ('ttl', c_ubyte),
        ('protocol_num', c_ubyte),
        ('sum', c_ushort),
        ('src', c_ulong),
        ('dst', c_ulong),
        ("src_port", c_ushort),
        ("dst_port", c_ushort)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)  # 实例化类

    def __init__(self, socket_buffer=None):
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}  # 创建一个字典，协议字段与协议名称对应
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        # inet_ntoa()函数将字节流转化为点分十进制的字符串，专用于IPv4地址转换
        # 将c_ulong类型的src(源地址)转为小端的long类型数据，返回源地址的字节流格式
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
        # 协议判断
        try:
            self.protocol = self.protocol_map[self.protocol_num]  # 将协议号与协议名对应
        except:
            self.protocol = str(self.protocol_num)  # 若字典中没有，则直接输出协议号

