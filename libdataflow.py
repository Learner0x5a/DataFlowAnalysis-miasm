import os
from future.utils import viewitems, viewvalues
from utils import guess_machine

from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.expression.expression import get_expr_mem
from miasm.analysis.data_analysis import inter_block_flow #, intra_block_flow_raw
from miasm.core.graph import DiGraph
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.analysis.data_flow import DeadRemoval, ReachingDefinitions, DiGraphDefUse
from miasm.core.locationdb import LocationDB
from miasm.core.bin_stream_ida import bin_stream_ida

def intra_block_flow_symb(lifter, _, flow_graph, irblock, in_nodes, out_nodes):
    symbols_init = lifter.arch.regs.regs_init.copy()
    sb = SymbolicExecutionEngine(lifter, symbols_init)
    sb.eval_updt_irblock(irblock)
    print('*' * 40)
    print(irblock)


    out = sb.modified(mems=False)
    current_nodes = {}
    # Gen mem arg to mem node links
    for dst, src in out:
        src = sb.eval_expr(dst)
        for n in [dst, src]:

            all_mems = set()
            all_mems.update(get_expr_mem(n))

        for n in all_mems:
            node_n_w = (irblock.loc_key, 0, n)
            if not n == src:
                continue
            o_r = n.ptr.get_r(mem_read=False, cst_read=True)
            for i, n_r in enumerate(o_r):
                if n_r in current_nodes:
                    node_n_r = current_nodes[n_r]
                else:
                    node_n_r = (irblock.loc_key, i, n_r)
                if not n_r in in_nodes:
                    in_nodes[n_r] = node_n_r
                flow_graph.add_uniq_edge(node_n_r, node_n_w)

    # Gen data flow links
    for dst in out:
        src = sb.eval_expr(dst)
        nodes_r = src.get_r(mem_read=False, cst_read=True)
        nodes_w = set([dst])
        for n_r in nodes_r:
            if n_r in current_nodes:
                node_n_r = current_nodes[n_r]
            else:
                node_n_r = (irblock.loc_key, 0, n_r)
            if not n_r in in_nodes:
                in_nodes[n_r] = node_n_r

            flow_graph.add_node(node_n_r)
            for n_w in nodes_w:
                node_n_w = (irblock.loc_key, 1, n_w)
                out_nodes[n_w] = node_n_w

                flow_graph.add_node(node_n_w)
                flow_graph.add_uniq_edge(node_n_r, node_n_w)



def intra_block_flow_raw(lifter, ircfg, flow_graph, irb, in_nodes, out_nodes):
    """
    Create data flow for an irbloc using raw IR expressions
    """
    current_nodes = {}
    for i, assignblk in enumerate(irb):
        dict_rw = assignblk.get_rw(cst_read=True)
        current_nodes.update(out_nodes)

        # gen mem arg to mem node links
        all_mems = set()
        for node_w, nodes_r in viewitems(dict_rw):
            for n in nodes_r.union([node_w]):
                all_mems.update(get_expr_mem(n))
            if not all_mems:
                continue

            for n in all_mems:
                node_n_w = (hex(assignblk.instr.offset), i, n)
                if not n in nodes_r:
                    continue
                o_r = n.ptr.get_r(mem_read=False, cst_read=True)
                for n_r in o_r:
                    if n_r in current_nodes:
                        node_n_r = current_nodes[n_r]
                    else:
                        node_n_r = (hex(assignblk.instr.offset), i, n_r)
                        current_nodes[n_r] = node_n_r
                        in_nodes[n_r] = node_n_r
                    flow_graph.add_uniq_edge(node_n_r, node_n_w)

        # gen data flow links
        for node_w, nodes_r in viewitems(dict_rw):
            for n_r in nodes_r:
                if n_r in current_nodes:
                    node_n_r = current_nodes[n_r]
                else:
                    node_n_r = (hex(assignblk.instr.offset), i, n_r)
                    current_nodes[n_r] = node_n_r
                    in_nodes[n_r] = node_n_r

                flow_graph.add_node(node_n_r)

                node_n_w = (hex(assignblk.instr.offset), i + 1, node_w)
                out_nodes[node_w] = node_n_w

                flow_graph.add_node(node_n_w)
                flow_graph.add_uniq_edge(node_n_r, node_n_w)



def node2str(node):
    out = "%s,%s\\l\\\n%s" % node
    return out


def gen_function_data_flow_graph(lifter, ircfg, ad, block_flow_cb) -> DiGraph:
    '''
        generate data flow graph for a given function
    '''
    irblock_0 = None
    for irblock in viewvalues(ircfg.blocks):
        loc_key = irblock.loc_key
        offset = ircfg.loc_db.get_location_offset(loc_key)
        # print('{} -> {}'.format(hex(offset), irblock.loc_key))
        if offset == ad:
            irblock_0 = irblock
            break
    assert irblock_0 is not None
    flow_graph = DiGraph()
    flow_graph.node2str = node2str


    irb_in_nodes = {}
    irb_out_nodes = {}
    for label in ircfg.blocks:
        irb_in_nodes[label] = {}
        irb_out_nodes[label] = {}

    for label, irblock in viewitems(ircfg.blocks):
        block_flow_cb(lifter, ircfg, flow_graph, irblock, irb_in_nodes[label], irb_out_nodes[label])

    # for label in ircfg.blocks:
    #     print(label)
    #     print('IN', [str(x) for x in irb_in_nodes[label]])
    #     print('OUT', [str(x) for x in irb_out_nodes[label]])

    # print('*' * 20, 'interblock', '*' * 20)
    inter_block_flow(lifter, ircfg, flow_graph, irblock_0.loc_key, irb_in_nodes, irb_out_nodes)

    return flow_graph


def ida_dataflow_analysis(function_addr:int, function_name:str, output_dir:str, defuse_only: bool = False) -> None:
    
    loc_db = LocationDB()

    ###################### IDA specific #######################
    machine = guess_machine() 
    bin_stream = bin_stream_ida()
    
    # Populate symbols with ida names
    import idautils
    for ad, name in idautils.Names():
        if name is None:
            continue
        loc_db.add_location(name, ad)


    ###################### Reverse-tool-independent ######################
    
    mdis = machine.dis_engine(bin_stream, loc_db=loc_db, dont_dis_nulstart_bloc=True)
    mdis.follow_call = True
    lifter = machine.lifter_model_call(loc_db=loc_db)

    print('disassembling function: {}:{}'.format(hex(function_addr), function_name))
    asmcfg = mdis.dis_multiblock(function_addr)

    print('generating IR...')
    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
    deadrm = DeadRemoval(lifter)
    # deadrm(ircfg) # TODO: 这里会删掉一部分IR，需要研究一下

    with open(os.path.join(output_dir, '{}.asm2ir'.format(function_name)),'w') as f:
        # print('\tOFFSET\t|  ASM\t|  SRC ->  DST')
        f.write('\tOFFSET\t|  ASM\t|  SRC ->  DST\n')
        for lbl, irblock in ircfg.blocks.items():
            insr = []
            for assignblk in irblock:
                for dst, src in assignblk.iteritems():
                    # print('\t{}\t|  {}\t| {} -> {}'.format(hex(assignblk.instr.offset), assignblk.instr, src, dst))
                    f.write('\t{}\t|  {}\t| {} -> {}\n'.format(hex(assignblk.instr.offset), assignblk.instr, src, dst))

    if not defuse_only:
        block_flow_cb = intra_block_flow_raw # if args.symb else intra_block_flow_symb

        dfg = gen_function_data_flow_graph(lifter, ircfg, function_addr, block_flow_cb)
        open(os.path.join(output_dir,'{}_dfg.dot'.format(function_name)), 'w').write(dfg.dot())

    reaching_defs = ReachingDefinitions(ircfg)
    defuse = DiGraphDefUse(reaching_defs)
    open(os.path.join(output_dir,'{}_defuse.dot'.format(function_name)), 'w').write(defuse.dot())

    '''
    根据block_loc_key + assignblk_idx 可以推算出instr offset，所以这个def-use图也是可以对应回指令的
    '''
    LocKeyIdx2InstrOffset = {}
    for block in viewvalues(reaching_defs.ircfg.blocks):
        for index, assignblk in enumerate(block):
            LocKeyIdx2InstrOffset['{}_{}'.format(block.loc_key, index)] = hex(assignblk.instr.offset)

    # print(['{}:{}'.format(key,LocKeyIdx2InstrOffset[key]) for key in LocKeyIdx2InstrOffset])
    open(os.path.join(output_dir,'{}_LocKeyIdx2InstrOffset.map'.format(function_name)), 'w').write(
        '\n'.join(['{}:{}'.format(key,LocKeyIdx2InstrOffset[key]) for key in LocKeyIdx2InstrOffset]))


def miasm_dataflow_analysis(function_addr:int, function_name:str, output_dir:str, filepath:str, arch:str = "X86_64", defuse_only: bool = False) -> None:

    bin_stream = Container.from_stream(open(filepath, 'rb'), loc_db).bin_stream
    machine = Machine(arch)

    loc_db = LocationDB()
    mdis = machine.dis_engine(bin_stream, loc_db=loc_db, dont_dis_nulstart_bloc=True)
    mdis.follow_call = True
    lifter = machine.lifter_model_call(loc_db=loc_db)

    print('disassembling function: {}:{}'.format(hex(function_addr), function_name))
    asmcfg = mdis.dis_multiblock(function_addr)

    print('generating IR...')
    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
    deadrm = DeadRemoval(lifter)
    # deadrm(ircfg) # TODO: 这里会删掉一部分IR，需要研究一下

    with open(os.path.join(output_dir, '{}.asm2ir'.format(function_name)),'w') as f:
        # print('\tOFFSET\t|  ASM\t|  SRC ->  DST')
        f.write('\tOFFSET\t|  ASM\t|  SRC ->  DST\n')
        for lbl, irblock in ircfg.blocks.items():
            insr = []
            for assignblk in irblock:
                for dst, src in assignblk.iteritems():
                    # print('\t{}\t|  {}\t| {} -> {}'.format(hex(assignblk.instr.offset), assignblk.instr, src, dst))
                    f.write('\t{}\t|  {}\t| {} -> {}\n'.format(hex(assignblk.instr.offset), assignblk.instr, src, dst))

    if not defuse_only:
        block_flow_cb = intra_block_flow_raw # if args.symb else intra_block_flow_symb

        dfg = gen_function_data_flow_graph(lifter, ircfg, function_addr, block_flow_cb)
        open(os.path.join(output_dir,'{}_dfg.dot'.format(function_name)), 'w').write(dfg.dot())

    reaching_defs = ReachingDefinitions(ircfg)
    defuse = DiGraphDefUse(reaching_defs)
    open(os.path.join(output_dir,'{}_defuse.dot'.format(function_name)), 'w').write(defuse.dot())

    '''
    根据block_loc_key + assignblk_idx 可以推算出instr offset，所以这个def-use图也是可以对应回指令的
    '''
    LocKeyIdx2InstrOffset = {}
    for block in viewvalues(reaching_defs.ircfg.blocks):
        for index, assignblk in enumerate(block):
            LocKeyIdx2InstrOffset['{}_{}'.format(block.loc_key, index)] = hex(assignblk.instr.offset)

    # print(['{}:{}'.format(key,LocKeyIdx2InstrOffset[key]) for key in LocKeyIdx2InstrOffset])
    open(os.path.join(output_dir,'{}_LocKeyIdx2InstrOffset.map'.format(function_name)), 'w').write(
        '\n'.join(['{}:{}'.format(key,LocKeyIdx2InstrOffset[key]) for key in LocKeyIdx2InstrOffset]))


