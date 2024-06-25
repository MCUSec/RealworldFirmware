from pathlib import Path 
'''
the function used to filter the valid firmware and 
'''

xtensa_base_address = {}

def lang_str() -> str:
    return "Xtensa:LE:32:default"

def base_address(firmware: Path):
    return 0

def firm_valid(firmware: Path) -> Path:
    # name valid end 
    if xtensa_base_address.get(firmware.name) is not None:
        logging.info(f'Skip {firmware.name} because duplicate')
        return None
    xtensa_base_address[firmware.name] = 0
    info_file = firmware.with_name(firmware.name + '_firminfo.json')
    if not info_file.exists():
        logging.error(f'Skip: no info file for {firmware}, skip')
        return None
    ## Start info check 
    with open(info_file, 'r') as file:
        info_ = json.load(file)
    # architecture
    if (arch_ := info_.get('architecture')) is None or arch_ != 'xtensa':
        logging.debug(f'Skip: not xtensa firmware-{firmware}')
        return None
    return firmware

# xtensa not implement 
def create_handlers(program: 'ghidra.program.model.listing.Program', flat_api: 'ghidra.program.flatapi') -> int:
    return 0
