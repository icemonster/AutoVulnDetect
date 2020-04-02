from pwn import disasm
from srcAVD.summaries import *
import bap
import subprocess
import binascii
from srcAVD.utils import *
# PARSER STUFF _------------------------------------

def readDigit(data, i):
	digit = ''
	while data[i] != '\n':
		digit += data[i]
		i += 1
	return (digit, i-1) #Return new index (index of last digit)

class Program:
	def __init__(self, bapProg, concrete):
		''' Responsible for keeping the functions (main, etc) and loaded functions (__libc_start_main, etc) '''
		#self.prog = bapProg
		self.concrete = concrete

		#Keys -> Regions
		#Values -> BapIL/Summary
		self.loadedFuncs = {} #Takes in regions as keys. Bir lifted code as values.
		self.bilFuncs = bapProg #Takes in addresses. (size of Instruction, Bil lifted code) as values

	def getInstructionSize(self, addr):
		currentInstr = self.concrete.read_instructions(addr, 15)
		currentInstr = currentInstr.decode()
		currentInstr = getStringRepresentation(currentInstr)

		if config.ARCH == config.x86:
			arch = 'x86_32'
		else:
			arch = 'x86_64'
		res = subprocess.check_output(["bap-mc", currentInstr, "--show-size", arch, "--only-one"])
		return int(res.strip().decode())

	def getNextInstruction(self, ip):
		func = self.bilFuncs.get(ip, None)
		if func is not None:
			return ip + func[0]

		size = self.getInstructionSize(ip)
		return ip + size

	def getBlk(self, ip):
		''' Receives an address as argument and returns instructions to execute
				(basic block/function)
		'''

		#result: '__libc_start_main+0x0 in libc.so.6 (0x18d90)'
		func = self.concrete.ld.describe_addr(ip).split(' ')[0] 
		
		if '+' in func:
			func,offset = func.split('+')
		elif '-' in func:
			func,offset = func.split('-')
			
		func2 = func
		if func2.startswith('PLT.'):
			func2 = func2[4:]

		#Check in the summaries first
		if func2 in summaries and (not config.STRIPPED_BINARY or func.startswith('PLT.') and offset == '0x0'): #If there is a summary for the function...
			#If binary is stripped, its gg 
			return summaries[func2]

		#Then, check in the loaded functions
		func = self.bilFuncs.get(ip, None)
		if func is not None:
			return func[1]

		self.getCode(ip)
		if ip not in self.bilFuncs:
			return None
		return self.bilFuncs.get(ip)[1]

	def parseCode(self, addr, code):
		''' Called by getCode
			Responsible for filling the bilFuncs 
			addr --> Start address of code
			code --> Contains sizes of instructions '''

		oldAddr = addr #Save address here

		opens = ('(','[','"')
		closes = (')',']','"')

		if type(code) == bytes:
			code = code.decode()

		stack = []
		size = len(code)
		i = 0

		offset = 0x0
		token = ''

		while i < size:
			c = code[i]

			if stack == [] and c == '0':
				if code[i+1] == 'x':
					digit, i = readDigit(code, i+2)
					digit = int(digit, 16)
					#addr += offset #Instruction address
					offset = digit
			else:
				token += c

			if c in opens:
				stack.append(c)
			if c in closes:
				if c == '"' and stack[-2:] == ['"', '"']:
					stack = stack[:-2]
				elif c == ')':
					assert stack.pop() == '('
				elif c == ']':
					assert stack.pop() == '['

				#If we just closed a token
				if stack == []:
					self.bilFuncs[addr] = (offset, bap.bil.loads(token))

					addr = addr + offset
					offset = 0x0
					token = ''

			i += 1

		return self.bilFuncs[oldAddr][1]


	def getCode(self, addr):
		''' Fetch lifted code from addr '''

		ld = self.concrete.ld

		#Fetch object (e.g libc)
		obj = ld.find_object_containing(addr)

		if obj is None:
			return None

		#result: '__libc_start_main+0x0 in libc.so.6 (0x18d90)'
		func = ld.describe_addr(addr).split(' ')[0] 
		if '+' in func:
			func,offset = func.split('+')
		else:
			print('[program.py:getCode TODO - what to do with positive offset???')
			exit()


		if func in summaries: #If there is a summary for the function...
			return summaries[func]

		parser = lambda x: x
		adt_project_parser = {'load' : parser}

		offset = int(offset, 16)
		s = obj.symbols_by_name.get(func)

		if config.ARCH == config.x86:
			arch = 'x86_32'
		else:
			arch = 'x86_64'

		if s is not None and addr >= s.rebased_addr and addr < s.rebased_addr+s.size: #If that functions contains the address...
			size = s.size
			addr = s.rebased_addr

			code = self.concrete.read_instructions(addr, size) #Load code		
			code = getStringRepresentation(code)
			

			liftedCode = bap.run(code, bap='bap-mc', args=['--show-bil','adt', '--arch',arch, '--addr', hex(addr),'--show-size'], parser=adt_project_parser)
		else: #Its probably shady stuff. No matter!
			#size = self.getInstructionSize(addr) #This gives wrong results sometimes
			code = self.concrete.read_instructions(addr, 15)
			code = getStringRepresentation(code)

			liftedCode = bap.run(code, bap='bap-mc', args=['--show-bil','adt', '--arch',arch, '--addr', hex(addr),'--show-size','--only-one'], parser=adt_project_parser)
		
		return self.parseCode(addr, liftedCode)
