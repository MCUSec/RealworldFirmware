from pathlib import Path 
import os
import json
'''
the function used to filter the valid firmware and 
'''

arm_base_address = {}

def lang_str() -> str:
    return "ARM:LE:32:Cortex"

def remove_header(firmware: Path, info : dict) -> Path:
    file_offset = 0
    if info.get('file offset') is not None:
        file_offset = info['file offset']
    with open(firmware, 'rb') as input_file:
        input_file.seek(file_offset)
        remaining_data = input_file.read()
    noheader_ = firmware.with_name(firmware.name + 'noheader')
    with open(noheader_, 'wb') as output_file:
        output_file.write(remaining_data)
    return noheader_

def base_address(firmware: Path):
    if (ba_ := arm_base_address.get(firmware.name)) is None:
        logging.error(f"Ask for not check valid firmware {firmware.name}")
        return 0
    return ba_

def firm_valid(firmware: Path) -> Path:
    global arm_base_address
    if arm_base_address.get(firmware.name) is not None:
        logging.info(f'Skip: duplicated {firmware} file, skip')
        return None 
    logging.debug(f"Check {firmware.name} arm_valid start")
    # skip hard code
    if 'CoreNatureDictionary.ngram.mini.txt.table.bin.fs3569237fs' in firmware.name:
        logging.info("Skip CoreNature")
        return None
    if 'simulator_video' in firmware.name:
        logging.info("Skip simulator_video")
        return None
    # skip impossible hex
    # size > 10M 
    if os.path.getsize(firmware) > 0xa00000 and 'hex' in firmware.name:
        logging.error(f'Skip: too big {firmware}')
        return None
    # name valid end 
    info_file = firmware.with_name(firmware.name + '_firminfo.json')
    if not info_file.exists():
        logging.error(f'Skip: no info file for {firmware}, skip')
        return None
    ## Start info check 
    with open(info_file, 'r') as file:
        info_ = json.load(file)
    # architecture
    if info_.get('architecture') is None or info_['architecture'] != 'arm':
        logging.debug(f'Skip: not arm firmware-{firmware}')
        return None
    # base address
    base_address = 0
    if (ba_ := info_.get('base address')) is not None and ba_ != '0x-1': 
        if len(ba_) < 3 or ba_[:2] != '0x':
            logging.error(f'Skip: invalid base address str {ba_}')
        else:
            base_address = int(ba_[2:], base=16)
    arm_base_address[firmware.name] = base_address
    return remove_header(firmware, info_)

# for create handler functions 
def create_handlers(program: 'ghidra.program.model.listing.Program', flat_api: 'ghidra.program.flatapi') -> int:
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.symbol import RefType
    from ghidra.program.model.util   import CodeUnitInsertionException
    from ghidra.program.model.mem    import MemoryAccessException
    handler_name = ['MasterStackPointer', 'Reset_Handler', 'NMI_Handler', 'HardFault_Handler', 
     'MemManage_Handler', 'BusFault_Handler','UsageFault_Handler',
        'Reserved1_','Reserved2_','Reserved3_','Reserved4_',
     'SVC_Handler', 'Reserved5_','Reserved6_','PendSV_Handler','SysTick_Handler']
    i = 0
    # TODO: use num to count the successfully handler creation not the i
    num = 0
    program_len = int(program.getMaxAddress().subtract(program.getMinAddress()))
    image_base = int(program.getImageBase().getUnsignedOffset())
    while True:
        i += 1
        addr_ = flat_api.toAddr(image_base +4*i)
        try:
            handler_address = flat_api.getInt(addr_) - 1
        except MemoryAccessException:
            if i >= len(handler_name):
                break
            continue
        if handler_address == -1 or handler_address == 0xfffffffe:
            try:
                flat_api.createDWord(addr_)
            except CodeUnitInsertionException:
                pass 
            continue
        elif handler_address > image_base and (handler_address - image_base) < program_len:
            if i >= len(handler_name):
                name_ = 'IRQ' + str(i-16)+ '_Handler'
            else:
                name_ = handler_name[i]
            # create Data and reference 
            label_ = name_[:name_.find('_')]
            try:
                data_ = flat_api.createDWord(addr_)
                flat_api.createLabel(addr_, label_, True)
                flat_api.createMemoryReference(data_, flat_api.toAddr(handler_address), RefType.UNCONDITIONAL_CALL)
            except CodeUnitInsertionException:
                print(f"\033[31mCreate Handler failed addr:{hex(handler_address)}, name:{name_}\033[0m")
                continue
            # create Function 
            flat_api.disassemble(flat_api.toAddr(handler_address))
            newfunc = flat_api.createFunction(flat_api.toAddr(handler_address), name_)
            # rename thunk functions 
            if newfunc is None:
                  print(f"\033[31mCreate Function failed addr:{hex(handler_address)}, name:{name_}\033[0m")
            elif newfunc.getName()[:6] == 'thunk_':
                newfunc.setName(name_, SourceType.USER_DEFINED)
        else:
            return i 
            # not a correct handler 
            break

