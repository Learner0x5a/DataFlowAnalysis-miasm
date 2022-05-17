# ida-dfg

IDA Pro data-flow graph generator

Tested with IDA Pro 7.6 and miasm 7ee593d

## libdataflow.py

封装了两个核心接口给其他脚本用
 - `ida_dataflow_analysis`: 面向IDA + MIASM的场景
 - `miasm_dataflow_analysis`: 单独使用，不需要IDA Pro

## IDAGenDFG.py

IDAPython调用的脚本

`/path/to/ida -A -Lida.log -S"path/to/IDAGenDFG.py -o <output_dir>" /path/to/binary`

## deprecated/graph_dataflow.py

新版miasm支持的DFG/ReachinDefinition/DefUse分析

## deprecated/libdfg.py

代码升级 & debug工作停止，因为新版miasm自身支持dfg生成。

但是这部分代码的价值在于学习如何将miasm用到IDAPython里，详见`dataflow_analysis`函数。



## miasm的一些核心概念：
 - machine类： 定义架构、反汇编引擎、lifter
 - LocationDB类：各类数据结构的loc_key(unique id)，例如AsmBlock, IRBlock的loc_key；以及定义了offset和loc_key相互转换的函数
 - Instruction类：可以在miasm.core.cpu内查看其成员函数、变量
 - AsmCFG类、AsmBlock类：汇编控制流图、基本块
 - IRBlock类、AssignBlock类：AsmBlock经Lifter翻译得到IRBlock，每一个IRBlock有若干个AssignBlock
    * 每个AssignBlock对应一条IR赋值语句(src -> dst)，同时也可以对应回一条汇编指令(assignblk.instr)

## miasm的局限性

 - 反汇编较慢
 - 无法处理80bit浮点数
