# Trash Codes, consider doing it after load into ghidra 
import binwalk.core.plugin
import re

# Each plugin must be subclassed from binwalk.core.plugin.Plugin
class nvic_scan(binwalk.core.plugin.Plugin):
    '''
    A sample binwalk plugin module.
    '''
    # the scope of decompile to search 
    SEARCH_SCOPE = 0x1400
    STORE_SCOPE = 0x20
    MODULES = ['Signature']
    
    def b(self, i):
        return i.to_bytes(1, 'little')

    def use_def_analysis(self, rn, rstart, data, instsb, start, end):
        '''
        check the def-use chain of mpu usage 
        1. load and store instructions share the same register 
        2. the imm offset in the mpu range
        '''
        # This if for thumb or not store inst 
        # print(f'{instsb}, {rstart}')
        prefix = self.b(0xc0+rn) + b'\xf8'
        for i in range(start,end,4):
            if (i - rstart) < 0:
                continue 
            pat_ = prefix + self.b(i - rstart)
            idx_ = data.find(pat_)
            if idx_ > 0:
                return idx_
        #    return False
        # elif rstart <= 0xa0:
        # Now let's test the store instruction
        for i in range(start,end,4):
            # str instruction with correct imm and rt as rn 
            if i < rstart or (i - rstart) > 0x1f :
                continue
            # binary encoding of thumb str instruction
            # 0 1 1 B L imm5 Rn Rt
            # & 0xf7ff for "L"
            val = ((0x6000 | rn << 3 | (i- rstart) << 6 ) & 0xf7ff).to_bytes(2, 'little')
            pat = b'[' + self.b(val[0]) + b'-' + self.b(val[0] + 7) + b']' + self.b(val[1])
            pattern = re.compile(pat)
            for match in pattern.finditer(data): 
                return match.start()
        return 0
    
    def mpu_scan(self, result):
        '''
        seek the SEARCH SCOPE for instruction patterns
        variables:
            instsb: the load instruction bytes
            imm : the load offset
            rstart: the start address of original nvic address
        '''
        with open(result.file.name, 'rb') as file:
            if result.offset > self.SEARCH_SCOPE:
                file.seek(result.offset - 1 - self.SEARCH_SCOPE)
            data = file.read(self.SEARCH_SCOPE)
            nvic = file.read(4)
            rstart = nvic[0] # the start address of nvic 
        # pattern to search literal thumb ldr instructions 
        pattern = re.compile(b'[\x00-\xff][\x48-\x4f]')
        for match in pattern.finditer(data):    
            instsb = match.group()
            imm = instsb[0] << 2
            # 2 is one thumb inst length 
            # + 3 ) & 0xfffc to align 4 bytes 
            nvic_rt = (imm + 2 + match.start() + 3) & 0xfffc
            rt = instsb[1] & 0x7
            #print(f'{hex(result.offset)}, {nvic_rt}')
            if match.start() + self.STORE_SCOPE > len(data):
                data_str = data[match.start():match.start()+self.STORE_SCOPE]
            else:
                data_str = data[match.start():]
            if nvic_rt == self.SEARCH_SCOPE and (str_pos := self.use_def_analysis(rt, rstart, data_str, instsb, 0x94, 0xb8)) > 0:
                return [result.offset-self.SEARCH_SCOPE+match.start()-1, result.offset-self.SEARCH_SCOPE+match.start()+str_pos-1]
        # ldr [opcode16(dff8-f)][imm8][reg4][imm4]
        pattern = re.compile(b'\xdf[\xf8-\xff][\x00-\xff]{2}')
        for match in pattern.finditer(data):    
            instsb = match.group()
            imm = ((instsb[3] & 0xf) << 8) | instsb[2]
            # 4 is one normal inst lenghth
            nvic_rt = (imm + 4 + match.start() + 3) & 0xfffc
            rt = instsb[3] >> 4
            # if nvic_rt == self.SEARCH_SCOPE:
            #     print(f'{hex(result.offset-self.SEARCH_SCOPE+match.start())}, {instsb},{hex(nvic_rt)}')
            if match.start() + self.STORE_SCOPE > len(data):
                data_str = data[match.start():match.start()+self.STORE_SCOPE]
            else:
                data_str = data[match.start():]
            if nvic_rt == self.SEARCH_SCOPE and (str_pos := self.use_def_analysis(rt, rstart, data_str, instsb, 0x94, 0xb8)) > 0:
                return [result.offset-self.SEARCH_SCOPE+match.start()-1, result.offset-self.SEARCH_SCOPE+match.start()+str_pos-1]
        return 0 
    
    def smpu_scan(self, result):
        with open(result.file.name, 'rb') as file:
            if result.offset > self.SEARCH_SCOPE:
                file.seek(result.offset - 1 - self.SEARCH_SCOPE)
            data = file.read(self.SEARCH_SCOPE)
            nvic = file.read(4)
            rstart = nvic[0] # the start address of nvic 
        pattern = re.compile(b'[\x00-\xff][\x48-\x4f]')
        for match in pattern.finditer(data):    
            instsb = match.group()
            imm = instsb[0] << 2
            # 2 is one thumb inst length 
            # + 3 ) & 0xfffc to align 4 bytes 
            nvic_rt = (imm + 2 + match.start() + 3) & 0xfffc
            rt = instsb[1] & 0x7
            if match.start() + self.STORE_SCOPE > len(data):
                data_str = data[match.start():match.start()+self.STORE_SCOPE]
            else:
                data_str = data[match.start():]
            if nvic_rt == self.SEARCH_SCOPE and (str_pos := self.use_def_analysis(rt, rstart, data_str, instsb, 0x2c, 0x2d)) > 0:
                return [result.offset-self.SEARCH_SCOPE+match.start()-1, result.offset-self.SEARCH_SCOPE+match.start()+str_pos-1]
        # ldr [opcode16(dff8-f)][imm8][reg4][imm4]
        pattern = re.compile(b'\xdf[\xf8-\xff][\x00-\xff]{2}')
        for match in pattern.finditer(data):    
            instsb = match.group()
            imm = ((instsb[3] & 0xf) << 8) | instsb[2]
            # 4 is one normal inst lenghth
            nvic_rt = (imm + 4 + match.start() + 3) & 0xfffc
            rt = instsb[3] >> 4
            # if nvic_rt == self.SEARCH_SCOPE:
            #     print(f'{hex(result.offset-self.SEARCH_SCOPE+match.start())}, {instsb},{hex(nvic_rt)}')
            if match.start() + self.STORE_SCOPE > len(data):
                data_str = data[match.start():match.start()+self.STORE_SCOPE]
            else:
                data_str = data[match.start():]
            if nvic_rt == self.SEARCH_SCOPE and (str_pos := self.use_def_analysis(rt, rstart, data_str, instsb, 0x2c, 0x2d)) > 0:
                return [result.offset-self.SEARCH_SCOPE+match.start()-1, result.offset-self.SEARCH_SCOPE+match.start()+str_pos-1]
        return 0
     
    def pendsv_scan(self, result):
        with open(result.file.name, 'rb') as file:
            if result.offset > self.SEARCH_SCOPE:
                file.seek(result.offset - 1 - self.SEARCH_SCOPE)
            instb = file.read(self.SEARCH_SCOPE)
            nvic = file.read(4)
            matches = self.pendsv_pattern.finditer(instb)
        for match in matches:
            # register in mov.w insts,#0x10000000
            insts = match.group()
            mov_rt = insts[5] & 0xf 
            # different types 
            circums = [(0,6),(6,0),(6,8),(8,6)]
            for c in circums:
                if insts[c[0]+1] & 0xf8 == 0x48 and insts[c[1]+1] & 0xf8 == 0x60:
                    ldr = int.from_bytes(insts[c[0]:c[0]+2],'little')
                    str = int.from_bytes(insts[c[1]:c[1]+2],'little')
                    (str_imm,str_rn,str_rt) = ((str >> 6 & 0x1f) << 2,(str >> 3 & 0x7),(str & 0x7))
                    (ldr_rt,ldr_imm) = ((ldr >> 8 & 0x7),((ldr & 0xff) << 2))
                    # + 3 ) & 0xfffc to align 4 bytes 
                    nvic_rt = (match.start() + c[0] + ldr_imm + 2 + 3) & 0xfffc
                    if match.start() + c[0] + ldr_imm + 2 == self.SEARCH_SCOPE and ldr_rt == str_rn and mov_rt == str_rt and (nvic[0] + str_imm) == 4:
                        return True 
            return False 
        return False

    def init(self):
        # The [\x00-\xff]{2} surrounding is a little hard code, 
        # TODO: improve this hard code 
        # but this pattern is found in freertos,zephyr,RIOT,mbed 
        # \x4f\xf0\x80\x5 means inst - mov.w insts,#0x10000000 
        # This is used by most RTOS to trigger a pendsv interrupt 
        self.pendsv_pattern = re.compile(b'[\x00-\xff]{2}\x4f\xf0\x80[\x50-\x5f][\x00-\xff]{4}')
        return

    def new_file(self, fp):
        return

    def scan(self, result):
        if result.description.startswith('_SCB&MPU'):
            if self.pendsv_scan(result):
                result.description = '_PendSV,ARM,trigger pendsv interrupt'
            elif (offset_ := self.mpu_scan(result)) != 0:
                result.description = "_MPU,ARM,set mpu region, ldr at " + hex(offset_[0]) + " str at " + hex(offset_[1])
            else:
                result.valid = False 
        if result.description.startswith('_SMPU'):
            if (offset_ := self.smpu_scan(result)) != 0:
                result.description = "_SMPU,ARM, ldr at " + hex(offset_[0]) + " str at " + hex(offset_[1])
            else:
                result.valid = False
        return

    def post_scan(self):
        return
