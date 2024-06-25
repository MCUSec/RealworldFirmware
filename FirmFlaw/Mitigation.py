'''
Script to create Function ID database
'''
import time
import json
import signal
import argparse
import logging 
from pathlib import Path 
from utils.launcher import HeadlessLoggingPyhidraLauncher
log_time = time.strftime("%Y-%m-%d_%H:%M:%S")
   
quick_mode = False
MPU_START = 0xe000ed90
MPU_END   = 0xe000edb8
SMPU_ADDR = 0x4000052c

def timeout_handler(signum, frame):
    raise TimeoutError('Operation timed out')

def trustzone_mpu(program, monitor):
    inst_iter = program.getListing().getInstructions(True)
    res = []
    mpu = []
    smpu = []
    bxns_ = False
    sg_ = False 
    for inst in inst_iter:
        mnemonic = inst.getMnemonicString()
        # blxns cannot be recognized by ghidra currently
        if mnemonic.startswith('bxns lr'):
            bxns_ = True
        if mnemonic.startswith('sg'):
            sg_ = True
            monitor.setMessage(f'{inst.getMinAddress()}: {int}')
            logging.debug(f'    {inst.getMinAddress()}: {inst}')
            res.append(inst.getMinAddress().getOffset())
        if quick_mode and len(mpu) > 0 and len(smpu) > 0:
            continue 
        if mnemonic.startswith('ldr') or mnemonic.startswith('str'):
            if ( addr_ := inst.getAddress(1)) is None:
                continue
            # mpu 
            val_ = addr_.getOffset() 
            if MPU_START <= val_ <= MPU_END:
                mpu.append(inst.getMinAddress().getOffset())
            # smpu
            if val_ == SMPU_ADDR:
                smpu.append(inst.getMinAddress().getOffset())
    # both match 
    if not (sg_ and bxns_):
        res = []
    return (res, mpu, smpu)
        
        

# None secure world trustzone search
decomplib = None

def dec_high_func(program, addr, monitor):
    '''
    decompile addr related funtion to highfunction
    '''
    timeout = 60
    func = program.getListing().getFunctionContaining(addr)
    if func is None:
        logging.info(f"Undefinedfunc at address {addr}")
        monitor.setMessage(f"Undefinedfunc at address {addr}")
        return None
    dres = decomplib.decompileFunction(func, timeout, monitor)
    hfunc = dres.getHighFunction()
    return hfunc

def get_hfunc(func, monitor):
    timeout = 60
    dres = decomplib.decompileFunction(func, timeout, monitor)
    hfunc = dres.getHighFunction()
    return hfunc

def get_reg(program, idx):
    return program.getRegister("r" + str(idx)).getAddress()

def search_ns(hfunc, addr, depth, monitor):
    from ghidra.app.decompiler.component import DecompilerUtils
    from ghidra.program.model.address import Address
    from ghidra.program.model.pcode import PcodeOp

    calls_ = set()
    vs_ = []
    if depth == 3:
        logging.info(f"Reach depth limit when search Non Secure at {hfunc.getFunction()}")
        monitor.setMessage(f"Reach depth limit when search Non Secure at {hfunc.getFunction()}")
        return False
    # collect all varnodes 
    for v_ in hfunc.getVarnodes(addr):
        vs_.append(v_)
        for v__ in DecompilerUtils.getForwardSlice(v_):
            vs_.append(v__)
    # search pcodes 
    for v_ in vs_:
        # only care varnode as input 
        for pcode_ in v_.getDescendants():
            if pcode_.getOpcode() == PcodeOp.CALL:
                if pcode_ in calls_:
                    continue
                calls_.add(pcode_)
                program_ = hfunc.getFunction().getProgram()
                hfunc_ = dec_high_func(program_, pcode_.getInput(0).getAddress(), monitor)
                if hfunc_ is None:
                    logging.error(f"Undefinedfunc at {pcode_.getSeqnum().getTarget()} Pass")
                    monitor.setMessage(f"Undefinedfunc at {pcode_.getSeqnum().getTarget()} Pass")
                    continue 
                param_addr_ = get_reg(hfunc.getFunction().getProgram(), pcode_.getSlot(v_)-1)
                return search_ns(hfunc_, param_addr_, depth+1, monitor)
            # if indirect call and the varnode is the target address 
            elif pcode_.getOpcode() == PcodeOp.CALLIND and pcode_.getSlot(v_) == 0:
                monitor.setMessage(f"TrustZone-NS: Find Indirect CALL at {pcode_.getSeqnum().getTarget()}")
                logging.info(f"TrustZone-NS: Find Indirect CALL at {pcode_.getSeqnum().getTarget()}")
                return True
    return False

def trustzone_ns(program, monitor):
    # skip this
    return []
    global decomplib
    from ghidra.program.model.data import Undefined4DataType
    from ghidra.app.decompiler import DecompInterface
    res = []
    func_addr_ = set()
    if decomplib is None:
        decomplib = DecompInterface()
    decomplib.openProgram(program)
    for data_ in program.getListing().getDefinedData(True):
        # data type must right 
        if not isinstance(data_.getBaseDataType(), Undefined4DataType): 
            continue 
        if (val_ := data_.getValue()) is None:
            continue
        val_ = val_.getValue()
        # Secure .text segment is between 0x10000000 and 0x20000000
        if val_ >= 0x20000000:
            continue
        if val_ <  0x10000000:
            continue
        # Ti CC26x0 CC13x0 ROM API 
        if 0x10000180 <= val_ <= 0x100001dc:
            continue
        # Most to search RAM 
        if val_ >= 0x1ff00000:
            continue
        cunit_ = program.getListing().getCodeUnitAt(data_.getAddress())
        for ref_ in cunit_.getReferenceIteratorTo():
            ldr_addr = ref_.getFromAddress()
            dat_addr = ref_.getToAddress()
            func_ = program.getListing().getFunctionContaining(ldr_addr)
            if func_ is None:
                monitor.setMessage(f"Undefinedfunc from address {ldr_addr}")
                logging.info(f"UnDefinedfunc from address {ldr_addr}")
                continue
            if (func_, dat_addr) in func_addr_:
                continue
            func_addr_.add((func_, dat_addr))
            hfunc = get_hfunc(func_, monitor)
            if hfunc is None:
                monitor.setMessage(f"Cannot decompile HighFunc from func {func_}")
                logging.info(f"Cannot decompile HighFunc from func {func_}")
                continue 
            if search_ns(hfunc, dat_addr, 0, monitor):
                logging.info(f"Find Result for {hex(val_)}")
                res.append(dat_addr)
                if quick_mode:
                    decomplib.closeProgram()
                    return res 
    decomplib.closeProgram()
    return res
    
def mpu(progam, monitor):
    mpu_res = []
    for inst_ in program.getListing().getInstructions(True):
        menmonic = inst_.getMnemonicString()
        if mnemonic[:3] != 'ldr' and mnemonic[:3] != 'str':
            continue
        if 0xe000edb8 >= inst_.getAddress(1) >= 0xe000ed90:
            mpu_res 
    return
            
def write_result(name: str, match_num: list, match_addr: list): 
    if len(match_num) == 0 or len(match_num[0]) != 3:
        logging.error(f"Not match {name} result for write match num")
    with open(f'./res/{name}.csv', 'w') as file:
        file.write("Program, trustzone, time\n")
        for i in match_num:
            file.write(f'{i[0]}, {i[1]}, {i[2]}\n')
    if len(match_addr) == 0 or len(match_addr[0]) != 3:
        logging.error(f"Not match result {name} for write match address")
    with open(f'./res/{name}_addr.csv', 'w') as file:
        file.write("Program, addresses\n")
        for i in match_addr:
            file.write(f'{i[0]}, {i[1]}\n')

def skip(name: str) -> bool:
    if name.startswith('K2200'):
        return True
    return False

def main(args):
    signal.signal(signal.SIGALRM, timeout_handler)
    launcher = HeadlessLoggingPyhidraLauncher(verbose=True, log_path='./launch.log')
    launcher.start()
    # import 
    from ghidra.base.project import GhidraProject
    from ghidra.feature.fid.db import FidFileManager
    from ghidra.util.task import ConsoleTaskMonitor
    # create or open project 
    try:
        project = GhidraProject.openProject(args.project_path, args.project_name, True)
        logging.info(f'Opened project: {project.project.name}')
    except IOException:
        loggin.error(f'No this project {args.project_path}/{args.project_name}')
        return 

    monitor = ConsoleTaskMonitor()
    ns_match_num = []
    ns_match_addr = []
    tz_match_num = []
    tz_match_addr = []
    mpu_match_num = []
    mpu_match_addr = []
    smpu_match_num = []
    smpu_match_addr = []
    program_num = 0
    start_time = time.time()
    # real operation
    check_files = set()
    for file_ in project.getRootFolder().getFiles():
        name_ = file_.getName()
        if skip(name_):
            continue
        real_name_ = name_[:name_.find('noheader')]
        if name_[:name_.find('noheader')] in check_files:
            continue
        check_files.add(real_name_)
        program_ = project.openProgram('/', file_.getName(), True)
        logging.info(f"Search {name_} start")
        monitor.setMessage(f"Search {name_} start")

        # Trustzone secure and mpu
        start_ = time.time()
        if quick_mode:
            signal.alarm(60)
        else:
            signal.alarm(600)

        try:
            (matches, mpu, smpu) = trustzone_mpu(program_, monitor)
            time_ = time.time() - start_
        except TimeoutError:
            logging.error(f"{name_} instruction search timeout") 
            monitor.setMessage(f"{name_} instruction search timeout")
            time_ = -1
        if len(matches) > 0:
            monitor.setMessage(f"{name_} matches {len(matches)} sg trustzone inst")
            logging.info(f"{name_} matches {len(matches)} sg trustzone inst")
            tz_match_num.append([name_, len(matches), time_])
            tz_match_addr.append([name_, matches])
        if len(mpu) > 0:
            monitor.setMessage(f"{name_} matches {len(mpu)} mpu ldr/str inst")
            logging.info(f"{name_} matches {len(mpu)} mpu ldr/str inst")
            mpu_match_num.append([name_, len(mpu), time_])
            mpu_match_addr.append([name_, mpu])

        if len(smpu) > 0:
            monitor.setMessage(f"{name_} matches {len(smpu)} smpu ldr/str inst")
            logging.info(f"{name_} matches {len(smpu)} smpu ldr/str inst")
            smpu_match_num.append([name_, len(smpu), time_])
            smpu_match_addr.append([name_, smpu])

        # Trustzone ns 
        start_ = time.time()
        if quick_mode:
            signal.alarm(60)
        else:
            signal.alarm(600)
        try:
            tmatches = trustzone_ns(program_, monitor)        
            time_ = time.time() - start_
        except TimeoutError:
            logging.error(f"{name_} trustzone none secure search timeout") 
            monitor.setMessage(f"{name_} instruction search timeout")
            time_ = -1
        if len(tmatches) > 0:
            monitor.setMessage(f"{name_} matches {len(tmatches)} trustzone instructions")
            ns_match_num.append([name_, len(tmatches), time_])
            ns_match_addr.append([name_, tmatches])
            logging.info(f"{name_} matches {len(tmatches)} trustzone instructions")
        project.close(program_)
        program_num += 1

    # write results
    logging.info(f'Total Mitigation search Time {time.time()-start_time} for {program_num} programs')
    write_result(f'trustzone_s_{args.project_name}', tz_match_num, tz_match_addr)
    write_result(f'trustzone_ns_{args.project_name}', ns_match_num, ns_match_addr)
    write_result(f'MPU_{args.project_name}', mpu_match_num, mpu_match_addr)
    write_result(f'SMPU_{args.project_name}', smpu_match_num, smpu_match_addr)

    # end 
    project.close()
    logging.info("Finish, Exit")  

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Mitigation detector (TrustZone, MPU and SMPU) from ghdira project")
    parser.add_argument("project_path",type=Path,default=Path('./ghidra_projects'))
    parser.add_argument("project_name",default="arm_database_project")
    parser.add_argument("-q","--quick",action="store_true",help="quick mode")
    args = parser.parse_args()
    # log
    #LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_FORMAT="%(message)s"
    DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
    logging.basicConfig(filename=f'./logs/mitigation_{log_time}.log', level=logging.DEBUG, format=LOG_FORMAT, datefmt=DATE_FORMAT)
    try:
        if args.quick:
            logging.info("Quick Mode")
            quick_mode = True
        main(args)
    except KeyboardInterrupt:
        logging.error("Exit with keyboard")
        project.close()
