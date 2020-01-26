from srcAVD.utils import *
from srcAVD import config
from srcAVD.adt import *
import sys, time, random
from z3 import *

sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='unicode_escape')

class IOHandler:
	def __init__(self):
		self.buffer = [] #Buffer of bytes

	def receiveMore(self, until=('\n','\x00')):
		while not self.buffer or (self.buffer[-1] not in until):
			a = sys.stdin.read(1)
			if a == '':
				return None
			self.buffer.append(a)
		return 1

	def read(self, mem, until=None):
		''' Returns list of read values. List of symbolic values if config.SYM_EXEC is active '''
		if config.SYM_EXEC:
			assert until is None
			name = 'inp_{}'.format(mem.genSymName()) #Generate unique name for symbolic var
			var = BitVec(name, 8)
			mem.addSymVar(var)
			return [var] 

		s = []
		if self.buffer == []:
			if self.receiveMore() is None:
				return [None]

		s.append(ord(self.buffer.pop(0))) #Return bytes, not chars. It simplifies stuff
		if until is not None:
			while s[-1] not in ord(until):
				if self.buffer == []:
					try:
						if self.receiveMore(until) is None:
							return s
					except:
						if not self.buffer:
							return s
				s += self.buffer.pop(0)
		return s

	def unread(self, v):
		self.buffer.insert(0, v)


stdin = IOHandler()

class Summary():
	def __init__(self, funcName):
		self.fName = funcName
		self.args = None #In case another summary needs to execute this one
	def execute(self, executor, mem):
		''' Execute summary on some memory '''
		pass
	def loadArg(self, mem, typ, toLoad):
		if typ == int:
			return mem.load(toLoad, size=32).val

		elif typ == str:
			if config.ARCH == config.x86:
				val = mem.load(toLoad, size=32).val
			else:
				val = mem.load(toLoad, size=64).val

			string = getString(mem, val)
			return string

		elif typ == chr:
			val = mem.load(toLoad, size=8).val
			if isSymbolic(val):
				return val
			else:
				return chr(val)

		elif typ == Pointer:
			if config.ARCH == config.x86:
				return mem.load(toLoad, size=32).val
			else:
				return mem.load(toLoad, size=64).val

		else:
			assert 1 == 0, "Unexpected argument type: " + str(arg)

	def loadArgs(self, mem, types):
		if self.args is not None:
			return self.args

		args = []
		if config.ARCH == config.x86:
			ebp = mem.load(config.ARCH.spReg).val #stack pointer is not saved yet and we dont even need to do that
			for arg in types:
				ebp = ebp + 4
				args.append(self.loadArg(mem, arg, ebp))
				
		else:
			argsRegs = ('RDI','RSI','RDX','RCX','R8','R9')
			i = 0
			sizeArgs = len(types)
			sizeRegs = len(argsRegs)
			
			if sizeArgs > sizeRegs: #Optimization
				ebp = mem.load(config.ARCH.spReg).val

			toLoad = getNextArg(mem)
			while i < sizeArgs:
				arg = types[i]

				args.append(self.loadArg(mem, arg, toLoad))
				toLoad = getNextArg(mem, toLoad)
				if (arg == Pointer or arg == str) and config.ARCH != config.x86 and type(toLoad) == int:
					toLoad = getNextArg(mem, toLoad) #Pointers are 64-bits in 64-bit binaries

				i += 1

		return args

	def ret(self, mem, retVal=None, size=None):
		''' Return intruction '''
	
		if size is None:
			size = config.ARCH.size 

		if retVal is not None:
			if config.ARCH == config.x86 and size == 64:
				#https://users.pja.edu.pl/~jms/qnx/help/watcom/compiler-tools/ccall32.html#ReturningValues
				mem.store('EDX', ADT(retVal >> 32))

			if not isSymbolic(retVal):
				retVal = twoComplement(retVal, size)
			mem.store(config.ARCH.retReg, ADT(retVal))

		#If another summary is executing us, we dont want to pop return address. 
			#that would just mean extra work
		if self.args is None:
			retAddr = mem.pop().val
			mem.setIP(retAddr)


class doNothing(Summary):
	def __init__(self):
		super().__init__('doNothing')
	def execute(self, executor, mem):
		self.ret(mem)

#Useful for entries and leavings
class libcStartMain(Summary):
	def __init__(self):
		super().__init__('__libc_start_main')
	def execute(self, executor, mem):
		''' Non-intuitively, If it gets here, its because its finished'''
		mem.hlt = True

class libcExit(Summary):
	def __init__(self):
		super().__init__('exit')
	def execute(self, executor, mem):
		mem.hlt = True
#----------------------------------

#Output summaries
class libcPuts(Summary):
	def __init__(self):
		super().__init__('puts')
	def execute(self, executor, mem):
		res = self.loadArgs(mem, [str])[0]
		res = res[:-1] #Remove trailing \0

		for v in res:
			if not isSymbolic(v):
				print(v, end='')
			else:
				print('[sym]', end='')
		print('') #Trailing newline

		self.ret(mem)

class libcPrintf(Summary):
	def __init__(self):
		super().__init__('printf')
	def execute(self, executor, mem):
		formatString = self.loadArgs(mem, [str])[0]
		formatString = formatString[:-1] #Cut down nullbyte

		if any(map(isSymbolic, formatString)):
			toPrint = ''
			for c in formatString:
				if isSymbolic(c):
					val = singleValue(mem, c)
					if val is None:
						toPrint += '<sym>'
					else:
						toPrint += chr(val)
				else:
					toPrint += c

			formatString = toPrint

		nextArg = getNextArg(mem)
		nextArg = getNextArg(mem, nextArg) #Get the second argument
		numWritten, parsedStr = parseFormatString(mem, nextArg, formatString)
		for i in parsedStr:
			if isSymbolic(i):
				print('<sym>', end='')
			else:
				print(i, end='')

		self.ret(mem, numWritten)

class libcSnprintf(Summary):
	def __init__(self):
		super().__init__('snprintf')
	def execute(self, executor, mem):
		destStr, size, formatString, = self.loadArgs(mem, [Pointer, int, str])
		formatString = formatString[:-1] #Cut down nullbyte

		if isSymbolic(size):
			size = maximize(mem, size)

		if any(map(isSymbolic, formatString)):
			toPrint = ''
			for c in formatString:
				if isSymbolic(c):
					val = singleValue(mem, c)
					if val is None:
						toPrint += '<sym>'
					else:
						toPrint += chr(val)
				else:
					toPrint += c

			formatString = toPrint

		nextArg = getNextArg(mem)
		nextArg = getNextArg(mem, nextArg) #Get the second argument
		numWritten, parsedStr = parseFormatString(mem, nextArg, formatString)

		for i in range(min(size, len(parsedStr))):
			if type(parsedStr[i]) == str:
				mem.storeByte(destStr + i, ADT(ord(parsedStr[i]))) #FIXME - Taint is not propagated
			else:
				mem.storeByte(destStr + i, ADT(parsedStr[i])) #FIXME - Taint is not propagated
		self.ret(mem, numWritten)
		

class libcPutchar(Summary):
	def __init__(self):
		super().__init__('putchar')
	def execute(self, executor, mem):
		val = self.loadArgs(mem, [chr])[0]
		
		if isSymbolic(val):
			print('<sym>', end='')
		else:
			print(val, end='')

		self.ret(mem, val)

#-----------------------------------------

#Input summaries
class libcGets(Summary):
	def __init__(self):
		super().__init__('gets')

	def execute(self, executor, mem):
		stringAddr = self.loadArgs(mem, [Pointer])[0]

		if config.SYM_EXEC: #FIXME - do something like angr when they want to provide symbolic input		
			# gets can fill up the stack with user input for all we know
				#but that would be really slow. Making it able to fill up
				#the last stack frame should be good enough
			
			for i in mem.concrete.memmap:
				if i.name == '[stack]':
					break 

			assert i.name == '[stack]'
			if i.containsAddr(stringAddr): #If we are using gets for a string in the stack...
				oldEBP = mem.load(config.ARCH.bpReg).val #Get last stack frame
				oldEBP = mem.load(oldEBP).val #Stored EBP

				if oldEBP > stringAddr:
					symInpLen = oldEBP - stringAddr
				else:
					symInpLen = i.end_address - stringAddr
			else:
				symInpLen = 1000 #FIXME - How much symbolic input?

			currSymSize = len(mem.gm.symVars)
			mem.gm.addSymMetaData((currSymSize, currSymSize+symInpLen-1, '\n'))
			
		i = 0
		while 1: #Need space for '\0'
			c = stdin.read(mem)[0]
			if c is None: #EOF
				break
			mem.storeByte(stringAddr, ADT(c))
			stringAddr += 1
			if c == ord('\n'):
				break

			i += 1
			if config.SYM_EXEC and i > symInpLen:
				break

		mem.storeByte(stringAddr, ADT(ord('\x00')))

		self.ret(mem, stringAddr)


class libcFgets(Summary):
	def __init__(self):
		super().__init__('fgets')
	def execute(self, executor, mem):
		stringAddr, size, stream = self.loadArgs(mem, [Pointer, int, int])

		#Assume stream is stdin
		
		if isSymbolic(size):
			size = maximize(mem, size)
	
		currSymSize = len(mem.gm.symVars)
		savedSize = size 

		while size > 1: #Need space for '\0'
			c = stdin.read(mem)[0]
			if c is None: #EOF
				break

			mem.storeByte(stringAddr, ADT(c))

			stringAddr += 1
			if c == ord('\n'):
				break
			size -= 1

		newSymSize = len(mem.gm.symVars)
		mem.gm.addSymMetaData((currSymSize, newSymSize-1, savedSize, '\n'))

		mem.storeByte(stringAddr, ADT(ord('\x00')))

		self.ret(mem, stringAddr)

class libcFread(Summary):
	def __init__(self):
		super().__init__('fread')
	def execute(self, executor, mem):
		ptr, size, nmemb, stream = self.loadArgs(mem, [Pointer, int, int, int])

		#assert stream == 0, "FIXME - We only fread from standard input"

		currSymSize = len(mem.gm.symVars)
		mem.gm.addSymMetaData((currSymSize, currSymSize + size*nmemb -1, size*nmemb))
		
		if isSymbolic(nmemb):
			nmemb = maximize(mem, nmemb)

		for i in range(nmemb):
			values = []
			symbolic = False
			for j in range(size):
				val = stdin.read(mem)[0]
				if val is None: #EOF
					self.ret(mem, i)
					return

				if isSymbolic(val):
					symbolic = True

				values.append(val)

			values = values[::-1] #Little endian
			if symbolic:
				if len(values) > 1:
					val = Concat(values)
				elif len(values) == 1:
					val = values[0]
				else:
					val = 0
			else:
				val = 0
				for j in values:
					val = val * 256 + j

			mem.store(ptr + i*size, ADT(val), size*8)

		self.ret(mem, nmemb)

class libcRead(Summary):
	def __init__(self):
		super().__init__('read')
	def execute(self, executor, mem):
		stream, stringAddr, size = self.loadArgs(mem, [int, Pointer, int])

		assert stream == 0, "FIXME - We only read from standard input"
		
		currSymSize = len(mem.gm.symVars)
		mem.gm.addSymMetaData((currSymSize, currSymSize+size-1, size))
		
		if isSymbolic(size):
			size = maximize(mem, size)

		bytesToRead = size


		while size > 0: #Need space for '\0'
			c = stdin.read(mem)[0]
			if c is None: #EOF
				self.ret(mem, 0)
				return

			mem.storeByte(stringAddr, ADT(c))
			
			stringAddr += 1
			size -= 1
		else:
			retVal = bytesToRead-size

		
		self.ret(mem, retVal)


class libcScanf(Summary):
	def __init__(self):
		super().__init__('fgets')
	def execute(self, executor, mem):
		formatString = self.loadArgs(mem, [str])[0]
		formatStr = formatString[:-1] #Cut down last byte
		assert formatStr == "%d" #FIXME - currently only supports %d

		formatString, intAddr = self.loadArgs(mem, [str, Pointer])
		
		if config.SYM_EXEC:
			#currSymSize = len(mem.gm.symVars)
			#mem.gm.addSymMetaData((currSymSize, currSymSize, size))
			#FIXME - This doesnt work with current way to get concrete input from tests because symvar is an int...
			name = 'Dinp_{}'.format(mem.genSymName()) #Generate unique name for symbolic var
			var = BitVec(name, 32)
			mem.store(intAddr, ADT(var))
		else:
			#i = input('Insert integer: ')
			i = stdin.read(mem, until=('\n','\x00'))
			i = ''.join(map(chr, i))
			i = int(i)
			mem.store(intAddr, ADT(i))

		self.ret(mem, 1) #Always return 1 because I assume it only supports %d (thus, 1 argument)


class libcGetchar(Summary):
	def __init__(self):
		super().__init__('getchar')
	def execute(self, executor, mem):
		currSymSize = len(mem.gm.symVars)
		mem.gm.addSymMetaData((currSymSize, currSymSize, 1))
		c = stdin.read(mem)[0]
		if c is None:
			c = 0
		
		self.ret(mem, c)


class libcUngetc(Summary):
	def __init__(self):
		super().__init__('ungetc')
	def execute(self, executor, mem):
		#FIXME - Shouldnt this receive an int?
		c, stream = self.loadArgs(mem, [int, Pointer])

		#assert stream == 0, stream

		stdin.unread(c)

		self.ret(mem, c)
#-----------------------------------------------------

#String manipulation summaries
class libcAtoi(Summary):
	def __init__(self):
		super().__init__('atoi')
	def execute(self, executor, mem):
		string = self.loadArgs(mem, [str])[0]
		string = string[:-1] #Cut down last byte

		val = int(string)

		self.ret(mem, val)

class libcIsPrint(Summary):
	def __init__(self):
		super().__init__('isprint')
	def execute(self, executor, mem):
		printable = '''!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~'''
		c = self.loadArgs(mem, [chr])[0]

		if not isSymbolic(c):
			if c in printable:
				self.ret(mem, 1) #If it is a printable character, it returns non-zero integer,
			else:
				self.ret(mem, 0)
		else:
			#It might be or not
			name = 'aux_{}'.format(mem.gm.genAuxSymName())
			val = BitVec(name, 32) #We assume result is only 0 (non printable) or 1 (printable) for simplicity
			
			printableConds = Or(map(lambda x: c == x, printable)) #Necessary conditions for char c to be printable
			mem.addRestr(Or(And(val == 0, Not(printableConds)), And(val == 1, printableConds)))


class libcStrchr(Summary):
	def __init__(self):
		super().__init__('strchr')

	def execute(self, executor, mem):
		#Strchr only receives an int for historical reasons... using int's here considering
		#	we use z3 bitvecs is asking for trouble
		s, c = self.loadArgs(mem, [Pointer, chr])

		symConds = []
		differentConds = []
		val = 0

		i = 0

		if not isSymbolic(c):
			c = ord(c)

		while 1:
			si = mem.loadByte(s + i).val

			if not isSymbolic(si) and not isSymbolic(c):
				if si == c:
					if not isSymbolic(val):
						val = s + i
					else:
						symConds.append(And(And(differentConds), val == s + i))
					break
			else:
				if mem.isItPossible(c == si):
					if not isSymbolic(val):
						name = 'aux_{}'.format(mem.gm.genAuxSymName())
						val = BitVec(name, 32)

						if isSymbolic(c):
							mem.gm.mapAuxToConcrete[val] = [c]
						else:
							mem.gm.mapAuxToConcrete[val] = [si]

					symConds.append(And(And(differentConds), c == si, val == s + i))

				if mem.isItPossible(si != c):
					differentConds.append(c != si)
				else: #If its not possible that si != c, then si == c for sure, thus we should break
					break

			if si == 0:
				if not isSymbolic(val):
					val = 0
				else:
					#Its possible that all characters were different and thus val = NULL
					symConds.append(And(And(differentConds), val == 0))
				break

			i += 1

		if isSymbolic(val):
			mem.addRestr(Or(symConds)) #One of them has to be true

		self.ret(mem, val)


class libcStrcmp(Summary):
	def __init__(self):
		super().__init__('strcmp')
	def execute(self, executor, mem):
		firstStr, secondStr = self.loadArgs(mem, [str, str])
		
		canBeDifferent = False
		canBeEqual = True 
		equalConds = []

		size1 = len(firstStr)
		size2 = len(secondStr)

		symVars = []

		if size1 < size2 and (not isSymbolic(secondStr[size1-1]) or not mem.isItPossible(secondStr[size1-1] == 0)): 
			canBeDifferent = True
			canBeEqual = False
		elif size1 > size2  and (not isSymbolic(firstStr[size2-1]) or not mem.isItPossible(firstStr[size2-1] == 0)):
			canBeDifferent = True
			canBeEqual = False
		else:
			for i in range(min(size1, size2)):
				c1 = firstStr[i]
				c2 = secondStr[i]

				if not isSymbolic(firstStr[i]):
					c1 = ord(c1)
				if not isSymbolic(secondStr[i]):
					c2 = ord(c2)

				if not isSymbolic(firstStr[i]) and not isSymbolic(secondStr[i]) and c1 != c2:
					canBeEqual = False
					canBeDifferent = True
					break
				else:
					if isSymbolic(firstStr[i]):
						symVars.append(firstStr[i])
					if isSymbolic(secondStr[i]):
						symVars.append(secondStr[i])

					if not mem.isItPossible(c1 == c2):
						canBeEqual = False 
						canBeDifferent = True
						break
					else:
						if mem.isItPossible(c1 != c2):
							canBeDifferent = True
						canBeEqual = True
						equalConds.append(c1 == c2)

		if canBeDifferent and canBeEqual:
			name = 'aux_{}'.format(mem.gm.genAuxSymName())
			val = BitVec(name, 32) #We assume result is only 0 (equal) or 1 (different) for simplicity
			mem.gm.mapAuxToConcrete[val] = symVars
				
			equalConds.append(val == 0)
			mem.addRestr(Or(And(equalConds), val == 1)) #Either all chars are equal and val == 0 or val == 1
			self.ret(mem, val)
		elif canBeDifferent: #If strings can only be different...
			self.ret(mem, 1)
		elif canBeEqual: #If strings can only be equal...
			self.ret(mem, 0)
			

class libcStrncmp(Summary):
	def __init__(self):
		''' Much like libcStrcmp but with upper bound for strings '''
		super().__init__('strncmp')
	def execute(self, executor, mem):
		firstStr, secondStr, n = self.loadArgs(mem, [str, str, int])
		
		canBeDifferent = False
		canBeEqual = True 
		equalConds = []

		if isSymbolic(n):
			#FIXME - This can cause false negatives
			n = maximize(mem, n)

		size1 = len(firstStr)
		size2 = len(secondStr)

		size1 = min(size1, n)
		size2 = min(size2, n)

		symVars = []

		if size1 < size2 and (not isSymbolic(secondStr[size1-1]) or not mem.isItPossible(secondStr[size1-1] == 0)): 
			canBeDifferent = True
			canBeEqual = False
		elif size1 > size2  and (not isSymbolic(firstStr[size2-1]) or not mem.isItPossible(firstStr[size2-1] == 0)):
			canBeDifferent = True
			canBeEqual = False
		else:
			for i in range(min(size1, size2)):
				c1 = firstStr[i]
				c2 = secondStr[i]

				if not isSymbolic(firstStr[i]):
					c1 = ord(c1)
				if not isSymbolic(secondStr[i]):
					c2 = ord(c2)

				if not isSymbolic(firstStr[i]) and not isSymbolic(secondStr[i]) and c1 != c2:
					canBeEqual = False
					canBeDifferent = True
					break
				else:
					if isSymbolic(firstStr[i]):
						symVars.append(firstStr[i])
					if isSymbolic(secondStr[i]):
						symVars.append(secondStr[i])

					if not mem.isItPossible(c1 == c2):
						canBeEqual = False 
						canBeDifferent = True
						break
					else:
						if mem.isItPossible(c1 != c2):
							canBeDifferent = True
						canBeEqual = True
						equalConds.append(c1 == c2)

		if canBeDifferent and canBeEqual:
			name = 'aux_{}'.format(mem.gm.genAuxSymName())
			val = BitVec(name, 32) #We assume result is only 0 (equal) or 1 (different) for simplicity
			mem.gm.mapAuxToConcrete[val] = symVars
				
			equalConds.append(val == 0)
			mem.addRestr(Or(And(equalConds), val == 1)) #Either all chars are equal and val == 0 or val == 1
			self.ret(mem, val)
		elif canBeDifferent: #If strings can only be different...
			self.ret(mem, 1)
		elif canBeEqual: #If strings can only be equal...
			self.ret(mem, 0)



class libcMemcmp(Summary):
	def __init__(self):
		super().__init__('memcmp')
	def execute(self, executor, mem):
		s1, s2, n = self.loadArgs(mem, [Pointer, Pointer, int])

		canBeDifferent = False
		canBeEqual = True 
		equalConds = []

		if isSymbolic(n):
			#FIXME - This can cause false positives
			n = maximize(mem, n)

		symVars = []

		for i in range(n):
			c1 = mem.loadByte(s1 + i).val
			c2 = mem.loadByte(s2 + i).val

			if not isSymbolic(c1) and not isSymbolic(c2) and c1 != c2:
				canBeEqual = False
				canBeDifferent = True
				break
			else:
				if isSymbolic(c1):
					symVars.append(c1)
				if isSymbolic(c2):
					symVars.append(c2)

				if not mem.isItPossible(c1 == c2):
					canBeEqual = False 
					canBeDifferent = True
					break
				else:
					if mem.isItPossible(c1 != c2):
						canBeDifferent = True
					canBeEqual = True
					equalConds.append(c1 == c2)

		if canBeDifferent and canBeEqual:
			name = 'aux_{}'.format(mem.gm.genAuxSymName())
			val = BitVec(name, 32) #We assume result is only 0 (equal) or 1 (different) for simplicity
			mem.gm.mapAuxToConcrete[val] = symVars
				
			equalConds.append(val == 0)
			mem.addRestr(Or(And(equalConds), val == 1)) #Either all chars are equal and val == 0 or val == 1
			self.ret(mem, val)
		elif canBeDifferent: #If strings can only be different...
			self.ret(mem, 1)
		elif canBeEqual: #If strings can only be equal...
			self.ret(mem, 0)

class libcMemcpy(Summary):
	def __init__(self):
		super().__init__('memcpy')
	def execute(self, executor, mem):
		firstStrAddr, secondStrAddr, nBytes = self.loadArgs(mem, [Pointer, Pointer, int])

		if isSymbolic(nBytes):
			nBytes = maximize(mem, nBytes)

		for i in range(nBytes):
			srcByte = mem.loadByte(secondStrAddr+i)
			mem.storeByte(firstStrAddr+i, srcByte)

		self.ret(mem, firstStrAddr) #The memcpy() function returns a pointer to dest.

class libcStrcpy(Summary):
	def __init__(self):
		super().__init__('strcpy')
	def execute(self, executor, mem):
		destAddr, srcAddr = self.loadArgs(mem, [Pointer, Pointer])

		c = 0
		while 1:
			srcByte = mem.loadByte(srcAddr+c)
			mem.storeByte(destAddr + c, srcByte)

			if srcByte.val == 0:
				break

			c += 1

		self.ret(mem, destAddr)


class libcStrncpy(Summary):
	def __init__(self):
		super().__init__('strcpy')
	def execute(self, executor, mem):
		destAddr, srcAddr, n = self.loadArgs(mem, [Pointer, Pointer, int])

		if isSymbolic(n):
			n = maximize(mem, n)

		c = 0
		while c < n:
			srcByte = mem.loadByte(srcAddr+c)
			mem.storeByte(destAddr + c, srcByte)

			if srcByte.val == 0:
				break
				
			c += 1

		self.ret(mem, destAddr)


class libcStrcat(Summary):
	def __init__(self):
		super().__init__('strcat')
	def execute(self, executor, mem):
		destAddr, srcAddr = self.loadArgs(mem, [Pointer, Pointer])

		destStrLen = len(getString(mem, destAddr)) - 1 #Exclude \0 from len

		i = 0
		while 1:
			srcByte = mem.loadByte(srcAddr+i)
			mem.storeByte(destAddr + destStrLen + i, srcByte)

			if srcByte.val == 0:
				break

			i += 1

		self.ret(mem, destAddr)


class libcStrlen(Summary):
	def __init__(self):
		super().__init__('strlen')
	def execute(self, executor, mem):
		s = self.loadArgs(mem, [str])[0]

		symConds = []
		differentConds = []
		val = 0
		symVars = []

		for i in range(len(s)):
			if isSymbolic(s[i]):
				symVars.append(s[i])
				if mem.isItPossible(s[i] == 0):
					if not isSymbolic(val):
						name = 'aux_{}'.format(mem.gm.genAuxSymName())
						val = BitVec(name, 32)
						

					#If all previous were not nullbyte and this one is, then val can be i
					symConds.append(And(And(differentConds), s[i] == 0, val == i))

				if mem.isItPossible(s[i] != 0):
					differentConds.append(s[i] != 0)
				else: #if it not possible that is different than zero, then it is zero for sure...
					break

			elif s[i] == '\x00':
				if not isSymbolic(val):
					val = i
				else:
					symConds.append(And(And(differentConds), val == i))
				break
			
		if isSymbolic(val):
			mem.addRestr(Or(symConds))
			mem.gm.mapAuxToConcrete[val] = symVars
		self.ret(mem, val) 

class libcStrtol(Summary):
	def __init__(self):
		super().__init__('strtol')
	def execute(self, executor, mem):
		nptr, endptr, base = self.loadArgs(mem, [Pointer, Pointer, int])
		initial = True
		sign = False

		assert not isSymbolic(base)

		s = getString(mem, nptr)
		size = len(s)

		number = ''

		i = 0
		while i < size:
			if s[i] == ' ' and initial: #Initial bytes might be whitespace ' '
				continue
			elif s[i] == '-' and initial: #Then, we MIGHT find a '-' or '+' sign
				inital = False
				sign = True
			elif s[i] == '+' and initial:
				initial = False
				sign = False
			else:
				initial = False
				if not base and (s[i:i+2] == '0x' or s[i:i+2] == '0X'):
					base = 16
					i = i + 1
				elif not base and s[i] == '0':
					base = 8
				elif not base:
					base = 10
					if s[i] >= '0' and s[i] <= '9':
						number += s[i]
					else:
						break
				elif base and i != size - 1: #not null byte
					try:
						_ = int(s[i], base)
						number += s[i]
					except:
						#At the end of the loop, i will be pointing to the first failed byte
						break 

			i = i + 1

		if number == '':
			nr = 0
			mem.store(endptr, ADT(nptr))
		else:
			nr = int(number, base) #This should succeed
			mem.store(endptr, ADT(nptr + i))

		if sign:
			nr = -nr

		nr = twoComplement(nr, size=32) #Long size is 32 usually
		self.ret(mem, nr)


class libcToupper(Summary):
	def __init__(self):
		super().__init__('toupper')
	def execute(self, executor, mem):
		c = self.loadArgs(mem, [chr])[0]
		if isSymbolic(c):
			self.ret(mem, If( And( UGE(c, 97), ULE(c, 122)), c - 32, c))
		else:
			self.ret(mem, ord(c.upper()))

class libcTolower(Summary):
	def __init__(self):
		super().__init__('tolower')
	def execute(self, executor, mem):
		c = self.loadArgs(mem, [chr])[0]
		if isSymbolic(c):
			self.ret(mem, If( And( UGE(c, 65), ULE(c, 90)), c + 32, c))
		else:
			self.ret(mem, ord(c.lower()))

#---------------------------------------------------------

#Randoms and stuff		
class libcTime(Summary):
	def __init__(self):
		super().__init__('time')
	def execute(self, executor, mem):
		tloc = self.loadArgs(mem, [int])[0]

		assert tloc == 0 #Assumes time function is always called with NULL argument
		secs = int(time.time())

		self.ret(mem, secs)

class libcSrand(Summary):
	def __init__(self):
		super().__init__('srand')
	def execute(self, executor, mem):
		seed = self.loadArgs(mem, [int])[0]

		mem.random = random.Random()
		mem.random.seed(seed)

		self.ret(mem)


class libcRand(Summary):
	def __init__(self):
		super().__init__('rand')
	def execute(self, executor, mem):

		#NOTE: Accurate on linux/windows
		RAND_MAX = 2147483647
		if mem.random is None:
			mem.random = random.Random()
			
		r = mem.random.randint(0, RAND_MAX)

		self.ret(mem, r)


class libcAbort(Summary):
	def __init__(self):
		super().__init__('abort')
	def execute(self, executor, mem):
		print('Abort was called!')
		sys.exit(1)


#------------------------------------------------------------

#Malloc functions
class libcMalloc(Summary):
	def __init__(self):
		super().__init__('malloc')
	def execute(self, executor, mem):
		size = self.loadArgs(mem, [int])[0] #Size in bytes!

		mem.inMalloc = True 

		if isSymbolic(size):
			#We want size to be as big as possible... Maybe? Possibly not
			size = maximize(mem, size)

		backupSize = size 

		if not mem.heapMetadata[0]:
			mem.initHeap()

		assert mem.heapMetadata[0]

		size_ptr = config.ARCH.size // 8 #in bytes

		size = size + 2 * size_ptr #Space for metadata
		if size % (size_ptr*2) != 0:
			size = size + size_ptr*2 - (size % (size_ptr*2)) #Memory align


		#TODO - Only save 1 free chunk and access the list (is it important to exploit double frees?)
		freeChunks = mem.heapMetadata[1]

		i = 0
		for chunk in freeChunks:
			if chunk[2] >= size: #If size of chunk is sufficient...
				break
			i += 1
		else:
			self.ret(mem, 0x0) #TODO - Add code that checks if a section is writable in mem.Store, etc.
			mem.inMalloc = False
			return

		indexOnList = i
		i = i + 1
		if i == len(freeChunks):
			i = 0

		#chunk[0] --> address of previous chunk (not necessarily free)
		#chunk[1] --> start address of chunk
		#chunk[2] --> size of chunk (i.e. free space, including metadata)

		#TODO - Change previous address of next free chunk (relative to the one we removed)

		freeChunks.remove(chunk)

		if chunk[2] != size:
			#Must split the chunk in two
			chunk1 = (chunk[0], chunk[1], size)
			size_second_chunk = (chunk[2] - size)

	
			chunk2 = (chunk[0], chunk[1]+size, size_second_chunk)

			#We wont use the second chunk
			freeChunks.insert(indexOnList, chunk2)
			chunk = chunk1

			#But we must update the next chunk information about him
			addr = chunk2[1]
			mem.store(addr + size_second_chunk, ADT(size_second_chunk))

			val = mem.load(addr + size_second_chunk + size_ptr).val
			val = val - (val % 8)
			mem.store(addr + size_second_chunk + size_ptr, ADT(val | 0b000))
		
		prev_chunk = chunk[0]
		addr = chunk[1]
		assert size == chunk[2]

		#We are not responsible for writing prev_size here (in mem[addr]) so we jump over it
		#And we just write the chunk size
		valReal = mem.load(addr+size_ptr)
		val = valReal.val
		val = val & 0b111 #Bits previously set in a possible malloc

		toStore = ADT(size | val)
		copyInformation(valReal, toStore)
		mem.store(addr + size_ptr, toStore)

		valReal = mem.load(addr + size_ptr)
		val = valReal.val

		#We are responsible for setting the information that the next chunk holds about this one here
		#Dont store size of previous chunk of next chunk (because its allocated now)
		
		val = 0b001 #AMP bits for next chunk. Everything belongs to the heap and chunk comes from main heap.
		old_val = mem.load(addr + size + size_ptr).val
		old_val = old_val - (old_val % 8) #Reset AMP bits


		toStore = ADT(old_val | val)
		copyInformation(valReal, toStore)
		mem.store(addr + size + size_ptr, toStore)

		#Update previous
		for i in range(len(freeChunks)):
			prev = i - 1
			if prev == -1:
				prev = len(freeChunks) - 1

			freeChunks[i] = (freeChunks[prev][1], freeChunks[i][1], freeChunks[i][2])

		#Return address to mem location (user data in the chunk)
		toReturn = addr + 2*size_ptr

		#Update allocated chunks list
		rang = MemRange(toReturn, toReturn + backupSize)
		mem.gm.allocatedRanges.append(rang)

		#print('DEBUG: Malloc- new chunk at -->', hex(addr))
		self.ret(mem, toReturn)
		mem.inMalloc = False


class libcCalloc(Summary):
	def __init__(self):
		super().__init__('calloc')
	def execute(self, executor, mem):
		nmemb, size = self.loadArgs(mem, [int, int])

		if isSymbolic(nmemb):
			nmemb = minimize(mem, nmemb)

		if isSymbolic(size):
			size = minimize(mem, size) #minimize in order to pass check. calloc should be safe for overflow

		size = nmemb * size
		if size > 0xFFFFFFFF: #Not a security vuln
			print('Calloc detected overflow')
			mem.hlt = True
			return

		s = libcMalloc()
		s.args = [size]
		s.execute(executor, mem)

		self.ret(mem) #No need to return value. Malloc already returned it, its on EAX/RAX


class libcRealloc(Summary):
	def __init__(self):
		super().__init__('realloc')
	def execute(self, executor, mem):
		''' To simplify, this realloc implementation always changes location of chunk.
				This free's the current chunk (passed as argument), allocates a new one
				with the designated size, and returns that one '''
		ptr, size = self.loadArgs(mem, [Pointer, int])

		if isSymbolic(size):
			#We want size to be as big as possible... Maybe? Possibly not
			size = maximize(mem, size)

		#Allocate size space
		s = libcMalloc()
		s.args = [size]
		s.execute(executor, mem)

		mem.inMalloc = True 

		#If  ptr  is  NULL,  then  the call is equivalent to malloc(size)
		if ptr == 0x0 and size != 0:
			self.ret(mem) #No need to return value. Malloc already returned it, its on EAX/RAX
			mem.inMalloc = False
			return

		elif size == 0:
			s = libcFree()
			s.args = [ptr]
			s.execute(executor, mem)

			self.ret(mem)
			mem.inMalloc = False
			return

		size_ptr = config.ARCH.size//8

		chunkAddr = ptr - 2 * size_ptr
		chunkSize = mem.load(chunkAddr + size_ptr).val
		chunkSize = chunkSize - (chunkSize % 8)
		chunkSize = chunkSize - 2 * size_ptr #Remove metadata from size

		#The contents will be unchanged in the range from the start of the region up to 
			#the minimum of the old and new sizes
		ptr2 = mem.load(config.ARCH.retReg).val

		for i in range(min(chunkSize, size)):
			mem.storeByte(ptr2 + i, mem.loadByte(ptr + i))

		#Free old space
		s = libcFree()
		s.args = [ptr]

		s.execute(executor, mem)


		#Return the newly allocated one
		self.ret(mem, ptr2)
		mem.inMalloc = False


class libcFree(Summary):
	def __init__(self):
		super().__init__('free')
	def execute(self, executor, mem):
		toFree = self.loadArgs(mem, [Pointer])[0] #Size in bytes!
		mem.inMalloc = True

		if (toFree == 0x0): #Assumes NULL is 0x0
			self.ret(mem)
			mem.inMalloc = False
			return

		assert toFree % 8 == 0
		size_ptr = config.ARCH.size//8

		chunkAddr = toFree - 2 * size_ptr #Subtract metadata
		chunkSize = getHeapChunkSize(mem, chunkAddr)

		#Store size of previous chunk of next chunk (because its not allocated now)
		mem.store(chunkAddr + chunkSize, ADT(chunkSize))

		#Mark it as free 
		valReal = mem.load(chunkAddr + chunkSize + size_ptr)
		val = valReal.val
		val = val - (val % 2)

		toStore = ADT(val)
		copyInformation(valReal, toStore)
		mem.store(chunkAddr + chunkSize + size_ptr, toStore)

		freeChunks = mem.heapMetadata[1]
		for i in range(len(freeChunks)):
			chunk = freeChunks[i]
			if chunk[1] > chunkAddr:
				break
		else:
			print(mem.heapMetadata)
			print(chunkAddr)
			print('Freeing invalid pointer:',toFree)
			self.ret(mem, -1)
			mem.inMalloc = False
			return

		nextChunk = chunk
		chunk = (nextChunk[0], chunkAddr, chunkSize) #previous of current is old previous of next
		freeChunks[i] = (chunkAddr,freeChunks[i][1],freeChunks[i][2]) #new previous of next is current
		prevChunkAddr = chunk[0]
		freeChunks.insert(i, chunk)

		#Now we write the chunk in memory as its supposed to be
		#----Size of previous chunk---- (done)
		#----Size of chunk -------------(done)
		#-----------Forward pointer ----(nextChunk[1])
		#-----------Back pointer -------(chunk[0])
		#-----------unused space--------(done)

		mem.store(chunkAddr + 2 * size_ptr, ADT(nextChunk[1]))

		if prevChunkAddr is None:
			mem.store(chunkAddr + 3 * size_ptr, ADT(freeChunks[-1][1])) #Circular list. Back to the last :)
		else:
			mem.store(chunkAddr + 3 * size_ptr, ADT(prevChunkAddr))

			#Here, update previous chunk forward pointer
			mem.store(prevChunkAddr + 2 * size_ptr, ADT(chunkAddr))


		#Update next free chunk metadata
		addr = nextChunk[1]
		mem.store(addr + 3 * size_ptr, ADT(chunkAddr)) #Only need to change back pointer to chunk

		mem.tryMergeFree(i) #Try to merge chunk and next
		if i != 0:
			mem.tryMergeFree(i-1) #Try to merge previous chunk and chunk


		#Update allocated chunks list
		ar = mem.gm.allocatedRanges
		for i in ar:
			if i.start == toFree:
				mem.gm.allocatedRanges.remove(i)
				break

		self.ret(mem)
		mem.inMalloc = False


#------------------------------------------------------------

class libcMemset(Summary):
	def __init__(self):
		super().__init__('memset')
	def execute(self, executor, mem):
		s, c, n = self.loadArgs(mem, [Pointer, int, int])
		
		if isSymbolic(n):
			n = maximize(mem, n)
			
		for i in range(n):
			#FIXME - What if c came from user input? We need to perserve tainting
			mem.storeByte(s + i, ADT(c & 0xFF))

		self.ret(mem, s)


class libcSystem(Summary):
	def __init__(self):
		super().__init__('system')
	def execute(self, executor, mem):
		cmd = self.loadArgs(mem, [str])
		
		print('[{}] Tried to execute a command: {}'.format(mem.memId, cmd[:-1]))

		self.ret(mem, 1)


class sysCalls(Summary):
	def __init__(self):
		super().__init__('int 0x80')
	def execute(self, executor, mem):
		code = mem.load(config.ARCH.retReg).val
		print('syscall code', hex(code))
		if code == 0x0: #Restart syscall
			print("Syscall - Restart syscall FIXME") #How to keep track of executed syscalls...
		elif code == 0x1:
			mem.htl = True
		elif code == 0x14: #Get pid
			pid = 6666 #Dummy pid
			mem.store(config.ARCH.retReg, ADT(pid))
		else:
			print('SYSCALL code not implemented!')
			terminate()


libc = libcStartMain()
summaries = {}

summaries['__libc_start_main'] = libcStartMain()
summaries['exit'] = libcExit() #There are a lot of useless stuff we dont care about when exiting
summaries['__cxa_atexit'] = libcExit()

summaries['puts'] = libcPuts()
summaries['_IO_puts'] = libcPuts()
summaries['printf'] = libcPrintf()
summaries['_IO_printf'] = libcPrintf()
summaries['putchar'] = libcPutchar()

summaries['getchar'] = libcGetchar()
summaries['ungetc'] = libcUngetc()
summaries['fgets'] = libcFgets()
summaries['_IO_fgets'] = libcFgets()
summaries['_IO_gets'] = libcGets()
summaries['gets'] = libcGets()
summaries['read'] = libcRead()
summaries['__isoc99_scanf'] = libcScanf()
summaries['fgetc'] = libcGetchar()
summaries['fread'] = libcFread()

summaries['strcmp'] = libcStrcmp()
summaries['strncmp'] = libcStrncmp()
summaries['__strncmp_sse42'] = libcStrncmp()
summaries['memcmp'] = libcMemcmp()
summaries['memcpy'] = libcMemcpy()
summaries['strcpy'] = libcStrcpy()
summaries['strncpy'] = libcStrncpy()
summaries['strcat'] = libcStrcat()
summaries['atoi'] = libcAtoi()
summaries['strchr'] = libcStrchr()
summaries['strtol'] = libcStrtol()
summaries['strlen'] = libcStrlen()
summaries['__strlen_avx2'] = libcStrlen()
summaries['isprint'] = libcIsPrint()

summaries['toupper'] = libcToupper()
summaries['tolower'] = libcTolower()

summaries['syscall'] = sysCalls()
summaries['setvbuf'] = doNothing()
summaries['_IO_setvbuf'] = doNothing()
summaries['__stack_chk_fail'] = doNothing()
summaries['__stack_chk_fail_local'] = doNothing()
summaries['alarm'] = doNothing()
summaries['system'] = libcSystem()
summaries['sleep'] = doNothing()

summaries['time'] = libcTime()
summaries['srand'] = libcSrand()
summaries['rand'] = libcRand()

summaries['malloc'] = libcMalloc()
summaries['free'] = libcFree()
summaries['calloc'] = libcCalloc()
summaries['memset'] = libcMemset()
summaries['realloc'] = libcRealloc()

#Testing stuff
summaries['abort'] = libcAbort()
