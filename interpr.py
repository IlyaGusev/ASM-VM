__author__ = 'allen'
from binascii import a2b_hex
from binascii import b2a_hex

#Table of commands:
#+: 01 to from type
#-: 02 to from type
#in: 03 to * type
#out: 04 from * type
#mov: 05 to from type
#ret: 06 from * *(
#arg: 07 what * type

#"RR": "00",
#"RD": "01",
#"RA": "02",
#"DR": "03",
#"DD": "04",
#"DA": "05",
#"AR": "06",
#"AD": "07",
#"AA": "08",


def i2b(i, s=4):
    return i.to_bytes(s, byteorder='big')

def b2i(b):
    return  int.from_bytes(b, byteorder='big')

def i2h(i):
    return "%0.2X" % i

def h2i(h):
    return b2i(a2b_hex(h))

def offset(var, kind):
    if kind == 'dec':
        return registers[var]
    elif kind == 'hex':
        return "%0.2X" % registers[var]

def is_int(value):
  try:
    int(value)
    return True
  except ValueError:
    return False

def reverse(st): return st[::-1]
reverse = lambda st: st[::-1]

commands = {'ADD': '01',
            'SUB': '02',
            'INP': '03',
            'OUT': '04',
            'MOV': '05',
            'RET': '06',
            'ARG': '07',
            'IFR': '08',
}
commands_inv = dict(zip(commands.values(), commands.keys()))

registers = {'CS': 0,
             'SS': 1,
             'DS': 2,
             'IP': 3,
             'SP': 4,
             'BP': 5,
             'DP': 6,
             'AX': 7,
             'BX': 8,
             'CX': 9,
             'RV': 10,
             'FS': 11
}
registers_inv = dict(zip(registers.values(), registers.keys()))
constants = {
    'RS': 16,
    'CS': 256,
    'SS': 1024,
    'DS': 256,
}

registers_values = {
    'CS': constants['RS'],
    'SS': constants['RS']+constants['CS'],
    'DS': constants['RS']+constants['CS']+constants['SS'],
    'DP': 0,
    'IP': 1,
    'SP': 0,
    'BP': 0,
    'AX': 0,
    'BX': 0,
    'CX': 0,
    'RV': 0,
    'FS': 0,
}

arg_types = {
    "RR": "00",
    "RD": "01",
    "RA": "02",
    "DR": "03",
    "DD": "04",
    "DA": "05",
    "AR": "06",
    "AD": "07",
    "AA": "08",
}
arg_types_inv = dict(zip(arg_types.values(), arg_types.keys()))

class MemoryContainer():
    def __init__(self, bytes = 4, size = 1024):
        self.memory = bytearray(b'\x00' * bytes * size)
        self.size = size
        self.bytes = bytes
    def __getitem__(self,key):
        return self.memory[key*self.bytes:(key+1)*self.bytes]
    def __setitem__(self,key,value):
        self.memory[key*self.bytes:(key+1)*self.bytes] = value


class Frame():
    def __init__(self, bytes= 4, size= 1024):
        self.memory = MemoryContainer(bytes, size)
        self.current = constants['RS']+1
        self.func = {}
        self.func_args = {}
        self.current_func = ''
        self.static = {}

    def get_abs_adr(self, rel, kind):
        if kind == 'D':
            return b2i(a2b_hex(rel))+registers_values['DS']
        elif kind == 'R':
            return b2i(a2b_hex(rel))
        elif kind == 'A':
            return b2i(self.memory[registers['SS']])+b2i(self.memory[registers['BP']])-17-b2i(a2b_hex(rel))

    def inc_reg(self, reg):
        self.memory[registers[reg]] = i2b(b2i(self.memory[registers[reg]])+1)

    def push(self, index):
        self.memory[b2i(self.memory[registers['SP']])+b2i(self.memory[registers['SS']])] = self.memory[index]
        self.inc_reg('SP')

    def load_registers(self):
        for i in range(16):
            self.push(i)
        self.memory[registers['FS']] = i2b(0)
        self.memory[registers['AX']] = i2b(0)
        self.memory[registers['BX']] = i2b(0)
        self.memory[registers['CX']] = i2b(0)

    def reload_registers(self):
        bp = self.memory[registers['BP']]
        self.memory[registers['AX']] = self.memory[b2i(self.memory[registers['SS']])+\
                                                               b2i(self.memory[registers['BP']])-constants['RS']+registers['AX']]
        self.memory[registers['BX']] = self.memory[b2i(self.memory[registers['SS']])+\
                                                               b2i(self.memory[registers['BP']])-constants['RS']+registers['BX']]
        self.memory[registers['CX']] = self.memory[b2i(self.memory[registers['SS']])+\
                                                               b2i(self.memory[registers['BP']])-constants['RS']+registers['CX']]

    def parse_arg(self, arg):
        if arg[0] == ' ':
            arg = arg[1:]
        if arg[0:2] in list(registers.keys()):
            return [offset(arg[0:2], 'hex'), 'R']
        elif arg in list(self.func_args[self.current_func]):
            return ["%0.2X" % int(self.func_args[self.current_func].index(arg)), 'A']
        elif arg.split(" ")[0] in list(self.func.keys()):
            print("!!!!!")
            args = arg.split(" ")[1:]
            for a in reverse(args):
                parsed = self.parse_arg(a)
                arg1 = parsed[0]
                arg3 = arg_types["R"+parsed[1]]
                self.set_command(a2b_hex(commands['ARG']+arg1+"00"+arg3))
            self.set_command(self.func[arg.split(" ")[0]])
            return [offset('RV', 'hex'), 'R']
        elif is_int(arg.replace(" ", '')):
            self.memory[registers_values['DP']+registers_values['DS']] = i2b(int(arg.replace(" ", '')))
            registers_values['DP'] += 1
            self.memory[registers['DP']] = i2b(registers_values['DP'])
            return ["%0.2X" % (registers_values['DP']-1), 'D']
        elif arg in (self.static.keys()):
            return ["%0.2X" % (self.static[arg]-registers_values['DS']), 'D']
        elif arg[0] == '"':
            self.memory[registers_values['DP']+registers_values['DS']] = a2b_hex("FF"+str("%0.2X" % len(arg[1:-1]))+"0000")
            registers_values['DP'] += 1
            self.memory[registers['DP']] = i2b(registers_values['DP'])
            for i in arg[1:-1]:
                self.memory[registers_values['DP']+registers_values['DS']] = i2b(ord(i))
                registers_values['DP'] += 1
                self.memory[registers['DP']] = i2b(registers_values['DP'])
            return ["%0.2X" % (registers_values['DP']-1-len(arg[1:-1])), 'D']
        else:
            return [0, 0]

    def set_command(self, command):
        self.memory[self.current]=command
        self.current += 1

    def save_bin(self, bin):
        bfile = open(bin, "wb")
        bfile.write(self.memory.memory)
        bfile.close()

    def asm_to_bin(self, asm, bin):
        afile = open(asm, "r")
        for key in list(registers.keys()):
            self.memory[registers[key]] = i2b(registers_values[key])

        for line in afile:
            line = line.replace('\n','')
            line = line.replace('\t', '')
            line = line.lstrip()
            line = line.rstrip()
            print(line)

            two_arg = ['ADD', 'MOV', 'SUB', 'IFR']
            one_arg = ['OUT', 'INP', 'RET']

            if line[0:3] in two_arg:
                vars = line.split(" ", 1)[1].split(',')
                parsed1 = self.parse_arg(vars[0])
                parsed2 = self.parse_arg(vars[1])
                arg1 = parsed1[0]
                arg2 = parsed2[0]
                arg3 = arg_types[parsed1[1]+parsed2[1]]
                self.set_command(a2b_hex(commands[line[0:3]]+arg1+arg2+arg3))

            elif line[0:3] in one_arg:
                parsed = self.parse_arg(line.split(" ", 1)[1])
                arg1 = parsed[0]
                arg3 = arg_types["R"+parsed[1]]
                self.set_command(a2b_hex(commands[line[0:3]]+arg1+"00"+arg3))

            elif line.find(':') != -1:
                func_name = line.split(':')[0].split(' ')[0]
                args = line.split(':')[0].split(' ')[1:]
                self.func[func_name] = i2b(self.current-constants['RS'])
                self.func_args[func_name] = args
                self.current_func = func_name
                if line.split(':')[0].split(' ')[0] == 'main':
                    registers_values['IP'] = self.current-registers_values['CS']
                    self.memory[registers['IP']] = i2b(registers_values['IP'])
            elif line.find('=') != -1:
                if line[0:2] in (registers.keys()):
                    reg = line.split('=')[0].replace(' ', '')
                    val = self.parse_arg(line.split('=')[1].replace(' ', ''))
                    self.memory[registers[reg]] = self.memory[self.get_abs_adr(val[0], val[1])]
                else:
                    val = self.parse_arg(line.split('=')[1])
                    key = line.split('=')[0].replace(' ', '')
                    self.static[key] = self.get_abs_adr(val[0], val[1])

            else:
                if line != '':
                    self.parse_arg(line)
        afile.close()
        self.save_bin(bin)

    def execute_bin(self):
        ip = b2i(self.memory[registers['IP']])+b2i(self.memory[registers['CS']])
        command = self.memory[ip]
        while command != (b'\x00'*4):
            hc = b2a_hex(command).decode('UTF-8')
            print(hc)
            if hc[0:2] in list(commands.values()):
                cn = hc[0:2]
                if cn == '01':
                    types = arg_types_inv[hc[-2:]]
                    self.memory[self.get_abs_adr(hc[2:4], types[0])] =\
                        i2b(b2i(self.memory[self.get_abs_adr(hc[2:4], types[0])])+\
                            b2i(self.memory[self.get_abs_adr(hc[4:6], types[1])]))
                elif cn == '02':
                    types = arg_types_inv[hc[-2:]]
                    self.memory[self.get_abs_adr(hc[2:4], types[0])] =\
                        i2b(b2i(self.memory[self.get_abs_adr(hc[2:4], types[0])])-\
                            b2i(self.memory[self.get_abs_adr(hc[4:6], types[1])]))
                elif cn == '03':
                    t = arg_types_inv[hc[-2:]][1]
                    s = int(input())
                    self.memory[self.get_abs_adr(hc[2:4], t)] = i2b(s)
                elif cn == '04':
                    t = arg_types_inv[hc[-2:]][1]
                    cell = (b2a_hex(self.memory[self.get_abs_adr(hc[2:4], t)])).decode('UTF-8')
                    if cell[:2] == 'ff':
                        s = ''
                        for c in range(h2i(cell[2:4])):
                            s += chr(b2i(self.memory[self.get_abs_adr(hc[2:4], t)+c+1]))
                        print(s)
                    else:
                        print(b2i(self.memory[self.get_abs_adr(hc[2:4], t)]))
                elif cn == '05':
                    types = arg_types_inv[hc[-2:]]
                    self.memory[self.get_abs_adr(hc[2:4], types[0])] = self.memory[self.get_abs_adr(hc[4:6], types[1])]
                elif cn == '06':
                    t = arg_types_inv[hc[-2:]][1]
                    self.memory[registers['IP']] = self.memory[b2i(self.memory[registers['SS']])+\
                                                               b2i(self.memory[registers['BP']])-constants['RS']+registers['IP']]
                    self.memory[registers['RV']] = self.memory[self.get_abs_adr(hc[2:4], t)]

                    self.reload_registers()
                    t = b2i(self.memory[b2i(self.memory[registers['SS']])+b2i(self.memory[registers['BP']])-constants['RS']+registers['FS']])
                    self.memory[registers['SP']] = i2b(b2i(self.memory[registers['SP']])-constants['RS']-t)
                    self.memory[registers['BP']] = i2b(b2i(self.memory[registers['BP']])-constants['RS']-t)


                elif cn == '07':
                    t = arg_types_inv[hc[-2:]][1]
                    self.push(self.get_abs_adr(hc[2:4], t))
                    self.inc_reg('FS')
                elif cn == '08':
                    types = arg_types_inv[hc[-2:]]
                    if b2i(self.memory[self.get_abs_adr(hc[2:4], types[0])]) != b2i(self.memory[self.get_abs_adr(hc[4:6], types[1])]):
                        self.inc_reg('IP')
                        ip = b2i(self.memory[registers['IP']])+b2i(self.memory[registers['CS']])
                        command = self.memory[ip]
                        hc = b2a_hex(command).decode('UTF-8')
                        while hc[0:2] == '07':
                            self.inc_reg('IP')
                            ip = b2i(self.memory[registers['IP']])+b2i(self.memory[registers['CS']])
                            command = self.memory[ip]
                            hc = b2a_hex(command).decode('UTF-8')

                self.inc_reg('IP')
            else:
                self.load_registers()
                self.memory[registers['IP']] = i2b(b2i(command))
                self.memory[registers['BP']] = self.memory[registers['SP']]
            ip = b2i(self.memory[registers['IP']])+b2i(self.memory[registers['CS']])
            command = self.memory[ip]

        self.save_bin("bin")

    def process_arg(self, h, t):
        abs_adr = self.get_abs_adr(h, t)
        if t == 'D':
            arg = self.memory[abs_adr]
            cell = (b2a_hex(arg)).decode('UTF-8')
            if cell[:2] == 'ff':
                s = '"'
                for c in range(h2i(cell[2:4])):
                    s += chr(b2i(self.memory[abs_adr+c+1]))
                s += '"'
                return s
            else:
                return str(b2i(arg))+' under '+str(abs_adr)
        elif t == 'R':
            return registers_inv[abs_adr]
        elif t == 'A':
            return "arg "+str(h2i(h))

    def bin_to_asm(self, dis):
        afile = open(dis, "w")
        two_arg = ['ADD', 'MOV', 'SUB', 'IFR']
        one_arg = ['OUT', 'INP', 'RET', 'ARG']
        arg_out = ""
        for i in range(constants['RS'], constants['RS']+  constants['CS']):
            st = b2a_hex(self.memory[i]).decode('UTF-8')
            if st[0:2] in list(commands.values()):
                command = commands_inv[st[0:2]]
                if command in one_arg:
                    t = arg_types_inv[st[-2:]][1]
                    arg = self.process_arg(st[2:4], t)
                    if command != 'ARG':
                        print(command+' '+str(arg))
                    else:
                        arg_out += str(arg)+', '
                elif command in two_arg:
                    type1 = arg_types_inv[st[-2:]][0]
                    type2 = arg_types_inv[st[-2:]][1]
                    arg1 = self.process_arg(st[2:4], type1)
                    arg2 = self.process_arg(st[4:6], type2)
                    print(command+' '+str(arg1)+','+str(arg2))

            elif st != "00000000":
                print("func on "+st+' with args '+arg_out)
                arg_out = ""
        afile.close()


if __name__ == "__main__":
    frame = Frame(4, 65000)
    frame.asm_to_bin("Examples/fab.txt", "bin")
    print('\n')
    frame.execute_bin()
    frame.bin_to_asm("dis.txt")
