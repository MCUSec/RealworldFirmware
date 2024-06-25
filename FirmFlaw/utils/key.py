#Define the key used for match 

# the lower bound for numaddress
LOWER_BOUND_ADDR_NUM = 20
INDIRECT = 61

def filter_func(func: 'ghidra.program.model.listing.Function') -> bool:
    '''
    filter the thunk function (just one inst to call other function) 
    and short functions ( smaller than 20 addresses )
    '''
    return not func.isThunk() and func.getBody().getNumAddresses() > LOWER_BOUND_ADDR_NUM

def get_inst_key(func: 'ghidra.program.model.listing.Function') -> tuple:
    '''
    get the number of addresses and the mnemonic string (split by ,) of this function 
    '''
    code_units = func.getProgram().getListing().getCodeUnits(func.getBody(), True)
    # TODO: consider convert tuple to dict to avoid use index to access the value 
    return (int(func.body.numAddresses),",".join(code.getMnemonicString() for code in code_units)) 


def get_opcode_key(decomplib: 'ghidra.app.decompiler.DecompInterface', func: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> tuple:
    '''
    get the number of op code and the opcode of every pcodeOp
    '''
    timeout = 60
    dres = decomplib.decompileFunction(func, timeout, monitor)
    hfunc = dres.getHighFunction()
    if hfunc is None:
        return (0,b'')
    ops_ = b''
    for pcode_ in hfunc.getPcodeOps():
        op_ = pcode_.getOpcode()
        if op_ == INDIRECT: # TODO: maybe more skip
            continue
        try:
            ops_ += op_.to_bytes(1)
        except OverflowError as e:
            logging.error(f"{op_} is too big")
    # TODO: use numAddreses or len(ops_)
    return (len(ops_), ops_)
    

def get_struct_graph_key(func: 'ghidra.program.model.listing.Function') -> tuple:  
    '''
    get the structure graph related attributes in this function
    such as blocks, edges, calls, jumps 
    '''
    # use this not flat_api.getMonitor() to avoid passing flat_api
    from ghidra.util.task import ConsoleTaskMonitor
    monitor = ConsoleTaskMonitor()
    from ghidra.program.model.block import BasicBlockModel
    block_model = BasicBlockModel(func.getProgram(), True)
    # all starts with 1 to prevent multiply zero 
    (num_blocks,num_edges,num_calls,num_jumps) = (1,1,1,1)
    for block in block_model.getCodeBlocksContaining(func.getBody(), monitor):
        num_blocks += 1
        num_edges += block.getNumDestinations(monitor)
        refs_ = block.getDestinations(monitor)
        while refs_.hasNext():
            ref_ = refs_.next()
            flow_type_ = ref_.getFlowType()
            if flow_type_.isCall():
                num_calls += 1
            elif flow_type_.isJump():
                num_jumps += 1
    # TODO: consider convert tuple to dict to avoid use index to access the value 
    return (num_blocks,num_edges,num_calls,num_jumps)

# TODO: add more keys 
