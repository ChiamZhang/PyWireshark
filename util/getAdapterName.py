
from scapy.all import *


def get_adapter_name():

    adapterName=['默认全部网卡']
    adapterInfor=show_interfaces(False)
    tem=adapterInfor.split('\n')
    for name in tem:
        a= name.strip().split('     ')
        if len(a)>3:
            adapterName.append(a[1].strip(' '))
    del(adapterName[1])
    # print(adapterName)
    return adapterName

def get_adapter_information():
    return show_interfaces(False)

