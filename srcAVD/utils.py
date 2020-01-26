from bap.bir import Blk
from z3 import *
from srcAVD import config
import time
import resource, os

def memory_limit():
	''' Limit RAM usage ''' 
	soft, hard = resource.getrlimit(resource.RLIMIT_AS)
	resource.setrlimit(resource.RLIMIT_AS, (get_memory() * 1024 * 9 / 10, hard))

def get_memory():
	with open('/proc/meminfo', 'r') as mem:
		free_memory = 0
		for i in mem:
			sline = i.split()
			if str(sline[0]) in ('MemFree:', 'Buffers:', 'Cached:'):
				free_memory += int(sline[1])
	return free_memory


class Pointer:
	pass

class MemRange:
	def __init__(self, start, end):
		self.start = start
		self.end = end

def twoComplement(n, size=32): 
	#if n is negative, this will actually be the 2complement :)
	#size = nr of bits of n
	return n & calcMod(size)


def bitIsSet(num, b):
	b = int('1' + '0'*b, 2)
	return num & b != 0

def calcMod(size):
	m = '1'*size
	return int(m, 2)

def getString(mem, addr):
	res = []
	while 1:
		val = mem.loadByte(addr)
		addr += 1
		if val.isSym:
			if not mem.isItPossible(val.val != 0):
				res.append('\x00')
				return res 

			res.append(val.val)
		else:
			res.append(chr(val.val))
			if val.val == 0:
				break

	if not any(map(isSymbolic, res)):
		return ''.join(res)
	else:
		return res

def getPossibleValue(mem, s):
	solver = mem.gm.solver 
	assert solver.check() == sat

	m = solver.model()

	val = m.evaluate(s)

	#If eval still returns symbolic variable (because s was not restricted maybe)
	if type(val) == BitVecRef:
		name = 'aux_' + mem.genSymName()
		b = BitVec(name, s.size())
		solver.add(b == s) #Restrict s :)
		assert solver.check() == sat
		m = solver.model()
		val = m.evaluate(s)

	assert type(val) == BitVecNumRef
	return val.as_long()

def singleValue(mem, s):
	''' Check is symbolic value s can only have 1 concrete value and return it.
			Return None otherwise '''

	solver = mem.gm.solver 
	val = getPossibleValue(mem, s)

	if not mem.isItPossible(s != val):
		mem.addRestr(s == val)
		return val 

	return None

#TODO - Rewrite this in a more uniform way
def parseFormatString(mem, addr, s):
	''' dumb format string parser '''
	numWritten = 0
	i = 0
	size = len(s)
	res = []
	while i < size:
		if s[i] == '%':
			
			if s[i+1] == 's':
				arg = mem.load(addr).val

				if type(addr) == int: #If its not a register...
					addr = getNextArg(mem, addr)

				s2 = getString(mem, arg)[:-1] #Cut down last byte
				numWritten += len(s2)
				#print(s2, end='')
				res += list(s2)
			elif s[i+1] == 'd' or s[i+1:].startswith('02d') or s[i+1:].startswith('04d'):
				arg = mem.load(addr, size=32).val
				if isSymbolic(arg):
					val = singleValue(mem, arg)
					if val is None:
						#print('<symD>', end='')
						res += list('<symD>') #FIXME snprintf
					else:
						#print(val, end='')
						res += list(str(val))
					numWritten += 1
				else:
					if arg & pow(2,31): #If MSB is set, its a negative number
						arg = -twoComplement(-arg)
					if s[i+1:].startswith('02d') or s[i+1:].startswith('04d'):
						val = ''
						if s[i+1:].startswith('04d'):
							if arg < 10:
								val = '000'
							elif arg < 100:
								val = '00'
							elif arg < 1000:
								val = '0'
						elif s[i+1:].startswith('02d'):
							if arg < 10:
								val = '0'

						#print(val, end='')
						res += list(val)
						numWritten += len(val)
						i += 2
					#print(arg, end='')
					res += list(str(arg))
					numWritten += len(str(arg))
				
			elif s[i+1] == 'x':
				arg = mem.load(addr, size=32).val
				#print(hex(arg)[2:], end='')
				res += list(hex(arg)[2:])
				numWritten += len(hex(arg))-2
			elif s[i+1] == 'l':
				arg = mem.load(addr, size=64).val

				if type(addr) == int: #If its not a register...
					addr = getNextArg(mem, addr)

				if s[i+2] == 'l' and s[i+3] == 'd':
					arg2 = mem.load(addr).val
					
					arg = arg2*pow(2,32)+arg
					if arg & pow(2, 63): #If MSB is set, its a negative number
						arg = -twoComplement(-arg)
					#print(arg, end='')
					res += list(str(arg))
					numWritten += len(str(arg))
					i += 2
			elif s[i+1] == 'c':
				arg = mem.loadByte(addr).val
				if isSymbolic(arg):
					#print('<symC>', end='') #FIXME snprintf
					res += ['?']
				else:
					#print(chr(arg), end='')
					res += [chr(arg)]
				numWritten += 1
			elif s[i+1] == 'p':
				arg = mem.load(addr).val
				if isSymbolic(arg):
					#print('<symAddr>', end='')
					res += list('<symAddr>') #FIXME snprintf
				else:
					#print(hex(arg), end='')
					res += list(hex(arg))
				numWritten += len(hex(arg))


			i += 1
			addr = getNextArg(mem, addr)
		else:
			#print(s[i], end='')
			res += list(s[i])
		i += 1
		
	return numWritten, res

def isSymbolic(val):
	return is_bv(val)

#FIXME - encode('unicode_escape') already does this
def getStringRepresentation(s, bts=True, beautify=False):
	if bts:
		assert type(s) == bytes

	res = ''
	for i in s:
		if bts:
			l = hex(i)[2:]
		else:
			l = hex(ord(i))[2:]
		l = l.zfill(2)

		if bts:
			l2 = i 
		else:
			l2 = ord(i)

		if beautify and (l2 >= ord('0') and l2 <= ord('9') or l2 >= ord('a') and l2 <= ord('z') or l2 >= ord('A') and l2 <= ord('Z')):
			if bts:
				res += chr(i)
			else:
				res += i
		else:
			res += '\\x' + l
	return res

def getInpVarsFromFormula(mem, formula, symVars):
	inpVars = set([])
	if formula.num_args() > 0:
		for arg in range(formula.num_args()):
			inpVars = inpVars.union(getInpVarsFromFormula(mem, formula.arg(arg), symVars))
	else:
		if 'aux' in str(formula): #If auxiliar variable...
			for dependence in mem.gm.mapAuxToConcrete[formula]:
				inpVars = inpVars.union(getInpVarsFromFormula(mem, dependence, symVars))
		elif formula.get_id() in symVars:
			inpVars.update([formula])

	return inpVars

def all_concrete_inputs(mem, minimized):
	s = mem.gm.solver
	symVars = mem.gm.symVars
	answers = []

	while mem.gm.solver.check() == sat:

		m = s.model()

		string = ''
		values = {}

		
		for v in m:
			name = v.name()
			if name.startswith('inp_'):
				name = name[4:]
				values[int(name)] = chr(m[v].as_long())

		ks = list(values.keys())
		ks.sort()
		for k in ks:
			string += values[k]

		answers.append(string)

		restrs = []
		for v in symVars:
			restrs.append(v != m[v].as_long())
		mem.gm.solver.add(Or(restrs))


	return answers

def concrete_input(mem, minimized=True):
	''' 
		Creates optimizer to give preference for inputs with "A"s
	'''

	if not config.SYM_EXEC:
		return '<concrete>'

	assert mem.gm.solver.check() == sat
	s = mem.gm.solver
	symVars = mem.gm.symVars

	#Prioritize input to use 'A's
	o = Optimize()
	for ass in s.assertions():
		o.add(ass)
	for v in symVars:
		o.add_soft(v == 0x41)

	assert o.check() == sat 

	m = o.model()

	string = ''
	values = {}

	#Build symbolic args result
	args = []
	for arg in config.ARGV:
		if type(arg) == int:
			args.append(['']*arg)
		else:
			args.append(list(arg))


	for v in m:
		name = v.name()
		if name.startswith('inp_'):
			name = name[4:]
			values[int(name)] = chr(m[v].as_long())
		elif name.startswith('Dinp_'): #Integer
			name = name[5:]
			values[int(name)] = str(m[v].as_long()) + ' '
		elif name.startswith('arg_'):
			name = name[4:]
			argI, argJ = map(int, name.split('_'))
			argI = argI - 1 #The index starts at 0
			args[argI][argJ] = chr(m[v].as_long())

	args = list(map(lambda x: ''.join(x), args))
	config.exploiting_args = args

	ks = list(values.keys())
	ks.sort()
	for k in ks:
		string += values[k]


	if minimized:
		string2 = string.rstrip('A') #Minimize input. FIXME - The A's in the end might be important...
		
		if string != string2:
			print('Try this if the string below doesnt work:',getStringRepresentation(string, bts=False))

		saveExploit(string2)

		return getStringRepresentation(string2, bts=False, beautify=True)
	else:
		saveExploit(string)

	print('Program Arguments:', config.exploiting_args)
	return getStringRepresentation(string, bts=False, beautify=True)

def addReasonableRestrToSym(mem, symAddr):
	''' Assumes symAddr is symbolic
			Adds restrictions so symAddr is on any of the available memory range.
			Returns False if it wasnt possible to add those restrictions '''

	possibleAddresses = []
	for i in mem.concrete.memmap:
		possibleAddresses.append(And(symAddr >= i.start_address, symAddr < i.end_address))

	if mem.start_of_heap is not None:
		possibleAddresses.append(And(symAddr >= mem.start_of_heap, symAddr < mem.end_of_heap))

	if mem.isItPossible(Or(possibleAddresses)):
		mem.addRestr(Or(possibleAddresses))
		return True

	return False

def addrIsReasonable(mem, addr):
	''' Assumes addr is concrete.
			Checks if addr is on one of the available memory ranges. '''
	if mem.start_of_heap is not None:
		if addr >= mem.start_of_heap and addr < mem.end_of_heap:
			return True

	for i in mem.concrete.memmap:
		if addr >= i.start_address and addr < i.end_address:
			return True

	return False

def getNextArg(mem, arg=None):
	if arg is None:
		if config.ARCH == config.x86:
			return mem.load(config.ARCH.spReg).val + 4
		else:
			return 'RDI'

	argsRegs = ('RDI','RSI','RDX','RCX','R8','R9')

	if arg not in argsRegs:
		return arg + 4

	i = argsRegs.index(arg)
	if i == len(argsRegs)-1: #First item on stack
		return mem.load(config.ARCH.spReg).val+4
	else:
		return argsRegs[i+1]


def get_name_outof_descr(descr):
	descr = descr.split(' ')
	name = descr[0]
	if '+' in name:
		return name.split('+')
	return name,'0x0'

def getHeapChunkSize(mem, chunkAddr):
	''' Arguments: Start of chunk (not data)
		Returns size of chunk '''

	size_ptr = config.ARCH.size//8

	#Size is always written in the second block of a chunk
	chunkSize = mem.load(chunkAddr + size_ptr).val

	return chunkSize - (chunkSize % 8) #3 bits of metadata

def isMetadata(gm, addr):
	''' Check if addr is heap metadata.
		TODO: Binary search.
		Assumes addr is on the heap '''
	ar = gm.allocatedRanges
	for i in ar:
		if addr >= i.start and addr < i.end: #end is exclusive
			return False

	return True

def addSoftExtreme(mem, bv, maximize=True):
	s = mem.gm.solver 

	#Prioritize input to use 'A's
	o = Optimize()
	for ass in s.assertions():
		o.add(ass)
	
	if maximize:
		o.maximize(bv)
	else:
		o.minimize(bv)

	assert o.check() == sat 

	m = o.model()
	val = m.evaluate(bv).as_long()

	s.add(bv == val)

	if isSymbolic(val): #If it was an unrestricted variable, return maximum size
		val = 2**val.size() - 1

	return val

def maximize(mem, bv):
	return addSoftExtreme(mem, bv)

def minimize(mem, bv):
	return addSoftExtreme(mem, bv, maximize=False)

#When you're so lazy that instead of modifying every single print instruction you have, you decide to do this
backupPrint = print
#outputFile = open('APG_output.txt','w')  #Use me if you uncomment the kargs['file'] line
already_written = 0
def print(*args, **kargs):
	global already_written #Just a bit of buffering in case we're using a file
	already_written += len(''.join(map(str,args)))

	if 'file' not in kargs:
		#kargs['file'] = outputFile #Use me whenever you want
		pass

	if already_written > 1024 and 'flush' not in kargs:
		kargs['flush'] = True
		already_written = 0
	backupPrint(*args, **kargs)

def logOnProfile(log):
	with open('{}.profile'.format(config.REAL_BINARY_NAME), 'a+') as f:
		f.write(time.ctime())
		f.write(': ')
		f.write(log)
		f.write('\n')

def terminate():
	end = time.time()
	diff = end - config.STARTED_TIME
	logOnProfile("Analysis done in a total of {} seconds".format(diff))

def saveExploit(exploit):
	if config.SAVE_EXPLOITS:
		with open('APG_input','wb') as f:
			f.write(bytes([ord(i) for i in exploit])) #Not the same thing as exploit.encode()!
