from pathlib import Path 
'''
the function used to filter the valid firmware and 
'''

def lang_str() -> str:
    return "ARM:LE:32:Cortex"

def base_address(firmware: Path):
    return 0

def firm_valid(firmware: Path) -> Path:
    return firmware

