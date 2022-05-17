import idc
import idautils
import idaapi
import ida_pro
import ida_auto
ida_auto.auto_wait()


for func in idautils.Functions():

    func_name = idc.get_func_name(func)
    print(hex(func),':',func_name)




ida_pro.qexit(0)
