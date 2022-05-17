import idaapi
import idautils
import idc
import ida_pro
import ida_auto
import os, sys
from libdataflow import ida_dataflow_analysis
from argparse import ArgumentParser

def main(OUTPUT_DIR:str) -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    textStartEA = 0
    textEndEA = 0
    for seg in idautils.Segments():
        if (idc.get_segm_name(seg)==".text"):
            textStartEA = idc.get_segm_start(seg)
            textEndEA = idc.get_segm_end(seg)
            break

    for func in idautils.Functions(textStartEA, textEndEA):
        # Ignore Library Code
        flags = idc.get_func_attr(func, idc.FUNCATTR_FLAGS)
        if flags & idc.FUNC_LIB:
            print(hex(func), "FUNC_LIB", idc.get_func_name(func))
            continue
        try:
            ida_dataflow_analysis(func, idc.get_func_name(func), OUTPUT_DIR, defuse_only=True)
        except Exception as e:
            print('Skip function {} due to dataflow analysis error: {}'.format(idc.get_func_name(func),e))

if __name__ == '__main__':
    if len(idc.ARGV) < 2:
        print('\n\nGenerating DFG & Def-Use Graph with IDA Pro and MIASM')
        print('\tNeed to specify the output dir with -o option')
        print('\tUsage: /path/to/ida -A -Lida.log -S"{} -o <output_dir>" /path/to/binary\n\n'.format(idc.ARGV[0]))
        ida_pro.qexit(1)

    parser = ArgumentParser(description="IDAPython script for generating dataflow graph of each function in the given binary")
    parser.add_argument("-o", "--output_dir", help="Output dir", default='./outputs', nargs='?')
    # parser.add_argument("-s", "--symb", help="Symbolic execution mode",
    #                     action="store_true")
    args = parser.parse_args()

    ida_auto.auto_wait()
    
    main(args.output_dir)
    
    ida_pro.qexit(0)