from avatar2 import *
import sys, cle
import subprocess
import ast

if len(sys.argv) != 2:
	print('Expecting a second argument = name of failed test')
	exit()

AVDTraceFile = "debugAVD.txt"
if not os.path.exists(AVDTraceFile):
    print('You must run AVD first in debug mode with the same binary')

name = sys.argv[1] #Name of failed test
print('Testing:', name)


def get_mappings(target):
    """Returns the mmap of the concrete process
    :return:
    """

    class MemoryMap:
        """
        Describing a memory range inside the concrete
        process.
        """
        def __init__(self, start_address, end_address, offset, name):
            self.start_address = start_address
            self.end_address = end_address
            self.offset = offset
            self.name = name

        def __str__(self):
            my_str = "MemoryMap[start_address: 0x%x | end_address: 0x%x | name: %s" \
                  % (self.start_address,
                     self.end_address,
                     self.name)

            return my_str

        def containsAddr(self, addr):
            return addr >= self.start_address and addr < self.end_address

    mapping_output = target.protocols.memory.get_mappings()

    mapping_output = mapping_output[1].split("\n")[4:]

    vmmap = []

    for mapp in mapping_output:
        mapp = mapp[2:].lstrip(' ')
        mapp = mapp.split(" ")

        # removing empty entries
        mapp = list(filter(lambda x: x not in ["\\t", "\\n", ''], mapp))

        map_start_address = mapp[0].replace("\\n", '')
        map_start_address = map_start_address.replace("\\t", '')
        map_start_address = int(map_start_address, 16)
        map_end_address = mapp[1].replace("\\n", '')
        map_end_address = map_end_address.replace("\\t", '')
        map_end_address = int(map_end_address, 16)
        offset = mapp[3].replace("\\n", '')
        offset = offset.replace("\\t", '')
        offset = int(offset, 16)
        if len(mapp) == 5:
            map_name = mapp[4].replace("\\n", '')
            map_name = map_name.replace("\\t", '')
            map_name = os.path.basename(map_name)
        else:
            map_name = 'unknown'
        vmmap.append(MemoryMap(map_start_address, map_end_address, offset, map_name))

    return vmmap


avatar = Avatar(arch=archs.x86.X86_64)

GDB_IP = '127.0.0.1'
GDB_PORT = 7070

target = avatar.add_target(GDBTarget, gdb_executable="gdb", gdb_ip=GDB_IP, gdb_port=GDB_PORT)   

cb_env = {'seed': '414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141'}

print(GDB_IP)
print(GDB_PORT)
print(name)

gdbserver = subprocess.Popen('gdbserver --once {}:{} {}'.format(GDB_IP, GDB_PORT, name), shell=True, env=cb_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

target.init()
entry = target.protocols.memory.get_symbol('main')
assert entry[0]
entry = entry[1]

target.set_breakpoint(entry)
target.cont()
target.wait(TargetStates.STOPPED)
#target.remove_breakpoint(entry)

#Synchronize cle loader with gdbserver. FIXME: Isn't there an option to do that already?  
memmap = get_mappings(target)
main_opts = {'base_addr': memmap[0].start_address}
lib_opts = {}
for i in memmap:  
    if i.name != 'unknown' and not i.name.startswith('['):
        if i.name not in lib_opts:
            lib_opts[i.name] = {'base_addr': i.start_address}   
ld = cle.Loader(name, lib_opts = lib_opts, main_opts=main_opts)

registers = ('rax', 'rbx', 'rcx', 'rdx', 'rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15','rip')

reportName = 'debugGDB.txt'
with open(reportName,'w') as f:
	pass

values = {}
main = ld.find_symbol('main')
finishLine = main.rebased_addr + main.size - 1
print('Main:', hex(main.rebased_addr))
print('Main finish:', hex(finishLine))

ip = target.read_register('rip')
while ip < finishLine:

	#Update register values
	ip = target.read_register('rip')
	for register in registers:
		values[register.upper()] = hex(target.read_register(register))

	#Update debug report
	with open(reportName,'a') as f:
		f.write(hex(ip)+'-')
		f.write(str(values)+'\n')
		
	#Go to next instruction
	target.step()
	target.wait(TargetStates.EXITED | TargetStates.STOPPED)

print('Done. Result in {}!'.format(reportName))

avatar.shutdown()
gdbserver.terminate()

print('Comparing both debug files...')

with open(reportName,'r') as f:
    real = f.read()

with open(AVDTraceFile,'r') as f:
    avd = f.read()

real = real.split('\n')
sizeReal = len(real)

avd = avd.split('\n')
sizeAVD = len(avd)

#Enforce same size
size = min(sizeReal, sizeAVD)
real = real[:size]
avd = avd[:size]

seenInstrs = []
seenRegs = []

for i in range(size):
    lineReal = real[i]
    lineAVD = avd[i]

    realIP, realReg = lineReal.split('-')
    avdIP, avdReg = lineAVD.split('-')

    assert realIP == avdIP, "AVD differed in execution here: " + avdIP + "(should be " + realIP + ")" #Well, at least these two should be the same

    realReg = ast.literal_eval(realReg)
    avdReg = ast.literal_eval(avdReg)

    for reg in realReg:
        if realReg[reg] != avdReg[reg]:
            if seenInstrs == []:
                print('Something went very wrong because values are inconsistent right before executing main.')
                print('Maybe you debugged a different binary with AVD?')
            else:
                print('Detected inconsistency in reg values here: ', seenInstrs[-1])
                print("These are the values of input")
                print(seenRegs[-1])
            print('These are the values of registers after executing instruction')
            print(avdReg)
            exit() #We only want to find the first inconsistency

    seenInstrs.append(realIP)
    seenRegs.append(avdReg)