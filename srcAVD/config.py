#This file holds DEFAULT values for some constants. They will be changed at runtime

class x86:
	size = 32
	name = 'x86'
	registers = ('EAX','EBX','ECX','EDX','ESI','EDI','EBP','ESP','EIP', 'YMM0', 'YMM1', 'YMM2','YMM3','YMM4','YMM5','YMM6','YMM7')
	ipReg = 'EIP'
	spReg = 'ESP'
	retReg = 'EAX'
	bpReg = 'EBP'

class x64:
	size = 64
	name = 'x64'
	registers = ('RAX', 'RBX', 'RCX', 'RDX', 'RSP','RBP','RSI','RDI','R8','R9','R10','R11','R12','R13','R14','R15','RIP', 'YMM0', 'YMM1', 'YMM2','YMM3','YMM4','YMM5','YMM6','YMM7')
	ipReg = 'RIP'
	spReg = 'RSP'
	retReg = 'RAX'
	bpReg = 'RBP'
	
#Architecture. Either x86 or x86_64 currently
ARCH = None

#Whether to execute the binary symbolically
SYM_EXEC = True

#Wheter to check for safety policies
EXEC_SAFETY_POLICIES = True

#Whether to try to find exploits
EXEC_EXPLOITS = not EXEC_SAFETY_POLICIES
SAVE_EXPLOITS = False
RETADDROF = 0x41414141

#Logging enabled
LOGGING = False

#Useful globals
BINARY_NAME = '' #FULL PATH
REAL_BINARY_NAME = '' #Only binary name
STARTED_TIME = 0 #Time where analysis started
TERMINATED = True
VULN_FOUND = False #Whether a vulnerability was found during the analysis

STRIPPED_BINARY = False
BASE_ADDR = None
IS_PIE = False

#Args
ARGC = 1
ARGV = [] #Excluding name of binary
exploiting_args = [] #To be filled by safety policies

GDB_IP = '127.0.0.1'
GDB_PORT = 9999