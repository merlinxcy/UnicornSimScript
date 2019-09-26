from unicorn import *
from unicorn.x86_const import *
x86_code = b"\x41\x4a"

address = 0x1000000

try:
    mc = Uc(UC_ARCH_X86, UC_MODE_32)
    mc.mem_map(address, 2*1024*1024)
    mc.mem_write(address, x86_code)
    mc.mem_write(address, x86_code)
    mc.reg_write(UC_X86_REG_ECX, 0x1234)
    mc.reg_write(UC_X86_REG_EDX, 0x7890)
    mc.emu_start(address, address + len(x86_code))

    r_ecx = mc.reg_read(UC_X86_REG_ECX)
    r_edx = mc.reg_read(UC_X86_REG_EDX)
    print(hex(r_ecx))
    print(hex(r_edx))
except Exception as e:
    print(e)
