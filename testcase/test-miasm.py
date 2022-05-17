import idc
import idautils
import idaapi
import ida_pro
import ida_auto
ida_auto.auto_wait()


from miasm.analysis.binary import Container
from miasm.core.asmblock import log_asmblock, AsmCFG
from miasm.core.interval import interval
from miasm.analysis.machine import Machine
from miasm.analysis.data_flow import \
    DiGraphDefUse, ReachingDefinitions, load_from_int
from miasm.expression.simplifications import expr_simp
from miasm.analysis.ssa import SSADiGraph
from miasm.ir.ir import AssignBlock, IRBlock
from miasm.analysis.simplifier import IRCFGSimplifierCommon, IRCFGSimplifierSSA
from miasm.core.locationdb import LocationDB

print("[+] miasm loading success.")

ida_pro.qexit(0)



