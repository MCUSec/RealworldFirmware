import os
import struct
import binwalk.core.plugin
import subprocess
import re


# Each plugin must be subclassed from binwalk.core.plugin.Plugin
class VendorMod(binwalk.core.plugin.Plugin):
    '''
    A sample binwalk plugin module.
    '''
    primary = ""
    description = ""
    size = 0
    chip = ""

    MODULES = ['Signature']

    # the function jumptable for every vendor
    # improve the speed and the code structure
    JumpTable = {}

    def telink(self, result):
        # TEST
        match = re.search(r'size (.*?),', result.description)
        if match:
            hexsize = match.group(1)
            decsize = int(hexsize)
            result.description += f" File size: {decsize},"
        return

    def qualcomm(self, result):
        # TEST
        chip_match = re.search(r'device variant (.*?),', result.description)
        if chip_match:
            self.chip = chip_match.group(1)

        # TEST
        match = re.search(r'size (.*?),', result.description)
        if match:
            hexsize = match.group(1)
            decsize = int(hexsize)
            self.size += decsize + 12
            result.description += f" Chip: {self.chip}, Component size: {self.size},"
        return

    def ti(self, result):
        if "msp430" in result.description.lower():

            file_name = result.file.name
            file_size = os.path.getsize(file_name)

            # file size from 0xFFFF to 0x20000
            if file_size >= 65535 and file_size < 131072:
                with open(file_name, 'rb') as file:
                    file.seek(65534 - 2 * 46)
                    values = [int.from_bytes(file.read(2), byteorder='little') for _ in range(46)]

                # values are 0 or within [8000 to FFFF]
                if all(32768 <= value <= 65408 or value == 0 for value in values):
                    result.description += f"File size: {file_size}"
                else:
                    print("Not all values are within the specified range.")
                    result.valid = False

        return

    def dialog(self, result):
        # TEST
        if 'Single' in result.description:
            match = re.search(r'size: (.*?),', result.description)
            if match:
                hexsize = match.group(1)
                decsize = int(hexsize) + 64
                result.description += f" File size: {decsize},"
        return

    def arm(self, result):
        file_name = result.file.name
        file_size = os.path.getsize(file_name)
        cnt = 0
        handlerthreshold = 13
        # We should check enough bytes to avoid false positive
        if result.offset > file_size - 0x40:
            result.valid = False
            return

        def count_valid(n):
            return n in (0, 0xFFFFFFFF) or (n < 0x20200000 and n % 2 == 1)
        
        # out of 15 handlers, count how many are valid
        with open(file_name, 'rb') as file:
            file.seek(result.offset + 4)  # Move the pointer to the handler table
            for _ in range(15):  # Read 15 4-byte integers
                data = file.read(4)  # Read 4 bytes
                if len(data) < 4:  # If less than 4 bytes are read, break the loop
                    break
                integer = struct.unpack('<I', data)[0]  # Convert bytes to integer (little endian)
                # print(hex(integer))
                if count_valid(integer):
                    cnt += 1
        # the threshold is 13
        if cnt < handlerthreshold:
            #print("cnt:" + hex(cnt))
            result.valid = False

        return

    def infineon(self, result):
        return

    # trigger this function before or after scan ?
    def esp(self, result):
        print('Inside esp signature plugin. File: ' + result.file.name)
        command = ["esptool.py", 'image_info', result.file.name]
        output = subprocess.run(command, capture_output=True, text=True)
        if output.returncode == 0:
            chip_string = ""
            size_string = ""
            entry_string = ""

            chip_pattern = re.compile(r'(?<=' + re.escape('Detected image type: ') + ')[^\n]*')
            size_pattern = re.compile(r'(?<=' + re.escape('File size: ') + ')[^\n]*')
            entry_pattern = re.compile(r'(?<=' + re.escape('Entry point: ') + ')[^\n]*')

            chip_match = chip_pattern.search(output.stdout)
            size_match = size_pattern.search(output.stdout)
            entry_match = entry_pattern.search(output.stdout)

            if chip_match:
                chip_string = chip_match.group(0)
            if size_match:
                size_string = size_match.group(0)
            if entry_match:
                entry_string = entry_match.group(0)

            result.description = f"_ESP, {chip_string}, Espressif Firmware Image, Xtensa, File size: {size_string}, Entry point: 0x{entry_string},"
        else:
            result.valid = False
        return
    
    def init(self):
        # Add content to JumpTable if new signatures is found
        self.JumpTable = {
			'Telink': self.telink,
			'Qualcomm': self.qualcomm,
			'Ti': self.ti,
			'Dialog': self.dialog,
			'ARM': self.arm,
			'Infineon': self.infineon,
			'ESP': self.esp,
		}
        return

    def pre_scan(self):
        return

    def new_file(self, fp):
        return

    def scan(self, result):
        # filter the results not pass the validation check and the output not by us
        if not result.valid or result.description[0] != '_':
            return
        vendor = result.description.split(',')[0][1:]
        #print(vendor)
        vendor_func = self.JumpTable.get(vendor)
        if vendor_func is None:
            return
        vendor_func(result)
        return

    def post_scan(self):
        return
