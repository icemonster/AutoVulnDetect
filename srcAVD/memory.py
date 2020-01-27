from srcAVD.utils import *
from srcAVD import config
from srcAVD.safetyPolicies import *
from srcAVD.adt import *
from pwn import *
from z3 import *

currentMem = 0

class Memory:
	def __init__(self, concrete, tlsM=None, uid=0):
		''' Argument "loader" --> cle.Loader.memory of binary, containing previously loaded shared libraries '''
		self.segmentRegs = ('GS_BASE','FS_BASE','ES_BASE','CS_BASE','SS_BASE','DS_BASE')
		self.flags = ('AF','ZF','PF','OF','CF','SF','DF')

		#First element --> Whether heap is initialized. Second --> list of free chunks
		self.heapMetadata = (False, [])
		self.start_of_heap = None
		self.end_of_heap = None
		self.concrete = concrete
		self.concreteMemory = False 

		self.jumped = False
		self.executedIf = False
		self.inMalloc = False #In case this function can mess with metadata...

		self.hlt = False
		self.basicBlk = 0x0 #Last IP that was in the heuristics
		self.status = []
		self.bt = [] #Backtrace
		self.bt2 = [] #Detailed backtrace
		self.ip = 0x0 #Special, because its used so often

		self.nextFunc = None #If there is a pending function to execute (goto's)
		self.nextRestr = [] #IF there are pending restrictions to add

		#Used to generate unique names for symbolic variables
		self.uid = uid
		self.random = None

		#Set memory unique identifier
		global currentMem
		self.memId = currentMem
		currentMem += 1

		self.writable = True #Set to False if you want this Memory to be const

		#Set of values that were pushed in the stack (like RIP and RBP) that should not be modified
		self.valuesToPerserve = []

		self.gm = None
		self.m = {}

		#FIXME - stack of memories
		if tlsM is not None:
			self.tlsM = tlsM
		else:
			self.tlsM = {}

	def addRestr(self, restr):
		self.gm.addRestr(restr)

	def isItPossible(self, restr):
		return self.gm.isItPossible(restr)

	def initHeap(self):
		#https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=blob;f=malloc/malloc.c;h=6e766d11bc85b6480fa5c9f2a76559f8acf9deb5;hb=HEAD#l1038
		ms = self.concrete.memmap
		name = ms[0].name #First section should be user code and stuff
		
		print('Mappings:')
		for m in self.concrete.memmap:
			print(m.name, '({}-{})'.format(hex(m.start_address), hex(m.end_address)))
		print('')

		for i in range(len(ms)):
			if ms[i].name != name:
				break 
		else:
			assert 1 == 0, "initHeap in APGExec.py: This shouldnt have happened"

		i = i - 1

		assert i >= 0 and ms[i].name == name
		start_of_heap = ms[i].end_address #heap should start here

		sAddrs = []

		for m in ms:
			
			#There may be already an heap in the mappings. Ignore it
			if m.start_address > start_of_heap:

					sAddrs.append(m.start_address)

		end_of_heap = min(sAddrs) #Heap shall occupy as much as it can :)
		
		#print('Initialized heap: ({}-{})'.format(hex(start_of_heap), hex(end_of_heap)))

		size_of_heap = (end_of_heap - start_of_heap)
		size_of_heap = size_of_heap - (size_of_heap % (config.ARCH.size//4))

		#Init with only 1 chunk (free) with size equal to heap size
		self.heapMetadata = (True, [(None, start_of_heap, size_of_heap)])
		self.start_of_heap = start_of_heap
		self.end_of_heap = end_of_heap

		size_ptr = config.ARCH.size // 8

		#Consider the first heap chunk (the top chunk) to be a freed chunk
		self.store(start_of_heap, ADT(0)) #size of previous chunk - #FIXME is this done for the first one?
		self.store(start_of_heap + size_ptr, ADT(size_of_heap | 0b001)) #size of previous chunk.
		self.store(start_of_heap + 2*size_ptr, ADT(start_of_heap)) #FP to next chunk in freed list. Point to itself
		self.store(start_of_heap + 3*size_ptr, ADT(start_of_heap)) #FP to previous chunk in freed list. Point to itself

	def tryMergeFree(self, i):
		''' Try to merge chunks freeChunks[i] and freeChunks[i+1] '''
		freeChunks = self.heapMetadata[1]
		size_ptr = config.ARCH.size // 8

		chunk = freeChunks[i]
		nextChunk = freeChunks[i+1]

		#chunk[0] --> address of previous chunk (not necessarily free)
		#chunk[1] --> start address of chunk
		#chunk[2] --> size of chunk (i.e. free space, including metadata)


		#Now we write the chunk in memory as its supposed to be
		#----Size of previous chunk---- (done)
		#----Size of chunk -------------(done)
		#-----------Forward pointer ----(nextChunk[1])
		#-----------Back pointer -------(chunk[0])
		#-----------unused space--------(done)

		addr = chunk[1]
		addr2 = nextChunk[1]

		#print('Trying to merge {} with {} bytes'.format(hex(addr), chunk[2]))
		#print('and {} with {} bytes'.format(hex(addr2), nextChunk[2]))

		if addr+chunk[2] == addr2: #If chunk ends when nextChunk begins, then we can merge!
			#print('Debugging: Merging {} with {}'.format(hex(addr), hex(addr2)))

			freeChunks.remove(chunk)
			freeChunks.remove(nextChunk)

			#Forward pointer of chunk points to next of next now
			fp = self.load(addr2 + 2 * size_ptr)
			self.store(addr + 2 * size_ptr, fp)
			fp = fp.val

			#Back pointer doesnt change (neither forward pointer of previous)

			#Backpoint of next should point to current
			self.store(fp + 3 * size_ptr, ADT(addr))

			i = 0
			for i in range(len(freeChunks)):
				if freeChunks[i][1] > addr:
					break
			else:
				i = i + 1

			#Size of new chunk is the sum of the sizes
			newChunk = (chunk[0], chunk[1], chunk[2] + nextChunk[2]) 
			freeChunks.insert(i, newChunk)

	def genSymName(self):
		self.uid = self.uid + 1
		return str(self.uid)

	def initMem(self):
		for f in self.flags: #Init flags
			self.store(f, ADT(0x0))

		for r in config.ARCH.registers:
			val = self.concrete.read_register(r)
			self.store(r, ADT(val))

		self.store('GS_BASE', TLSAccess(0x00))
		self.store('FS_BASE', TLSAccess(0x00))

	def setIP(self, ip):
		if self.writable:
			if type(ip) == str:
				ip = int(ip, 16)
			self.store(config.ARCH.ipReg, ADT(ip))
			self.ip = ip

	def getIP(self):
		return self.ip

	def delete(self, name):
		self.m.pop(name)

	def inMem(self, addr):
		if addr in self.m:
			return True

		assert self.gm is not None
		return self.gm.inMem(addr)

	def getFromMem(self, addr):
		if addr in self.m:
			return self.m[addr]

		assert self.gm is not None
		return self.gm.getFromMem(addr)

	def storeInMem(self, addr, val):
		self.m[addr] = val

	def addSymVar(self, symVar):
		self.gm.symVars.append(symVar)

	def updateValuesToPerserve(self, rsp):
		i = 0
		for i in range(len(self.valuesToPerserve)):
			if self.valuesToPerserve[i][0] <= rsp:
				break
		else:
			i = i + 1

		self.valuesToPerserve = self.valuesToPerserve[:i]

	def addValuesToPerserve(self, callsAndPushes, ip):
		for elem in callsAndPushes:
			if elem[0] == ip:
				rsp = config.ARCH.spReg
				#rspVal = self.load(rsp).val - config.ARCH.size//8 #addr where the pushed value will be
				rspVal = self.load(rsp).val #ITS *AFTER* the push is done that we run this code
				for i in range(config.ARCH.size // 8):
					self.valuesToPerserve.append((rspVal + i, elem[1]))


	def copy(self):

		new_mem = Memory(self.concrete, self.tlsM.copy(), self.uid)
		new_mem.basicBlk = self.basicBlk
		new_mem.heapMetadata = (self.heapMetadata[0], self.heapMetadata[1].copy())
		new_mem.bt = self.bt.copy()
		new_mem.bt2 = self.bt2.copy()
		new_mem.status = self.status.copy()
		if self.random is not None:
			new_mem.random = random.Random()
			new_mem.random.setstate(self.random.getstate()) #Keep random state across child memories
		new_mem.ip = self.ip
		new_mem.gm = self.gm
		new_mem.start_of_heap = self.start_of_heap
		new_mem.end_of_heap = self.end_of_heap
		new_mem.valuesToPerserve = self.valuesToPerserve.copy()

		for k in self.m:
			new_mem.m[k] = self.m[k].copy()

		return new_mem

	def loadByte(self, addr):
		oldAddr = addr 
		introduceTaintLeak = False

		if isSymbolic(addr): #This may be a vulnerability right away but lets continue
			addReasonableRestrToSym(self, addr) #Make the value belong to one of the available memory ranges
			addr2 = getPossibleValue(self, addr)
			self.addRestr(addr == addr2)
			addr = addr2

		if self.concreteMemory:
			return ADT(self.concrete.loadByte(addr))

		val = self.getFromMem(addr)
		if val is not None:
			val.tainted1 = val.tainted1 or introduceTaintLeak
			return val

		backupVal = self.concrete.canBeUndefined
		#if self.start_of_heap and addr >= self.start_of_heap and addr <= self.end_of_heap:
		if addrIsReasonable(self, addr): #If it belongs to any of the available memory ranges...
			#Careful that this is bypassed by use of unitilized values that could be different than 0
			self.concrete.canBeUndefined = True

		val = self.concrete.read_memory(addr, 1)

		self.concrete.canBeUndefined = backupVal

		if val is not None:
			res = ADT(u8(val))
			res.tainted1 = introduceTaintLeak
			return res
		else:
			inp = concrete_input(self, minimized=False)

			if isSymbolic(oldAddr):
				foundVuln('[!] Out-of-bounds Read. Tried to load symbolic addr {}'.format(oldAddr), self)
			else:
				if oldAddr == 0x0:
					foundVuln('[!] Read NULL Pointer Dereference', self)
				else:
					foundVuln('[!] Out-of-bounds Read. Tried to load addr {}'.format(hex(oldAddr)), self)
			return ADT(0x0)

			
		
	def load(self, addr, size=None, noneIsFine=False):
		if self.concreteMemory:
			return ADT(self.concrete.load(addr, size, noneIsFine))

		if size is None:
			size = config.ARCH.size

		if isSymbolic(addr): #This may be a vulnerability right away but lets continue
			addReasonableRestrToSym(self, addr) #Make the value belong to one of the available memory ranges
			addr2 = getPossibleValue(self, addr)
			self.addRestr(addr == addr2)
			addr = addr2

		if size == 1: #We only read bits from flags or vars actually
			assert type(addr) == str

		if type(addr) == str:
			val = self.getFromMem(addr)

			if val is not None:
				return val.twoComplement(size)

			if noneIsFine:
				return None

			self.printMemory()
			print('This shouldnt have happened... Tried to access', addr)
			terminate()

		#if size == 5: #FIXME malloc tries to access vars with 5 bits......... WHYYYYYY
		#	print('DEBUG: Tried to access a var with 5 bits')
		#	a = self.loadByte(addr).val
		#	return ADT(a & 0b11111)

		assert size >= 8 and size % 8 == 0, "size should be multiple of 8... instead is {}".format(size)
		s = size // 8
		

		l = [self.loadByte(addr+i) for i in range(s)]
		l = l[::-1] #Little endian

		if any(map(lambda x: x.isSym, l)): #If any of the loaded bytes are symbolic...
			l2 = []
			for v in l:
				if v.isSym:
					l2.append(v.val)
				else:
					l2.append(BitVecVal(v.val, 8)) #If its not symbolic, make it "symbolic"
			
			
			if len(l2) > 1:
				res = Concat(l2)
			else:
				res = l2[0]
		else:
			res = 0
			for i in l:
				res = res * 256 + i.val

		res = ADT(res)
		for i in l:
			copyInformation(i, res)

		return res

	def storeByte(self, dest, val):
		if self.concreteMemory:
			return self.concrete.storeByte(dest, val.val)

		if isSymbolic(dest): #This may be a vulnerability right away but lets continue
			addr2 = getPossibleValue(self, dest)
			self.addRestr(dest == addr2)
			dest = addr2

		#TODO MOVE all these to safety policies
		if config.EXEC_SAFETY_POLICIES and not addrIsReasonable(self, dest): #FIXME check write permissions too
			foundVuln('[!] Out-of-bounds Write on {}'.format(hex(dest)), self)

		if config.EXEC_SAFETY_POLICIES and self.start_of_heap is not None and self.end_of_heap is not None and not self.inMalloc:
			if dest >= self.start_of_heap and dest < self.end_of_heap and isMetadata(self.gm, dest):
				foundVuln('[!] Detected write on heap metadata. User tried to write {} on {}'.format(val, hex(dest)), self)

		spReg = self.load(config.ARCH.spReg).val
		if abs(spReg-dest) > config.ARCH.size//8 and config.EXEC_SAFETY_POLICIES:
			for valToPerserve in self.valuesToPerserve:
				if dest == valToPerserve[0]:
					foundVuln('[!] Buffer overflow detected. User tried to write on {}\n Which containted values that were pushed to the stack and should not be modified: {}'.format(hex(dest), valToPerserve[1]), self)

		if self.writable:
			assert (val.isSym and val.sz == 8) or val.val & 0xFF == val.val
			self.storeInMem(dest, val)

	def store(self, dest, val, size=None):
		if self.concreteMemory:
			return self.concrete.store(dest, val.val, size)
		
		if not self.writable:
			return 

		if size is None:
			size = config.ARCH.size

		if isSymbolic(dest): #This may be a vulnerability right away but lets continue
			dest = getPossibleValue(self, dest)

		if size == 1:
			assert type(dest) == str 

		if dest in config.ARCH.registers: #Registers are always ARCH size bits
			size = config.ARCH.size
			if dest == config.ARCH.spReg:
				if val.isSym:
					foundVuln("[!] RBP is being controlled by user")

				self.updateValuesToPerserve(val.val)

		if type(dest) == str:
			if dest == config.ARCH.ipReg:
				self.ip = val.val

			if type(val) == TLSAccess:
				self.storeInMem(dest, twoComplement(val, size))
			else:
				self.storeInMem(dest, val.twoComplement(size))

		else:
			while size > 0:
				if val.isSym:
					if size > 8:
						valByte = val.Extract(7, 0)
						copyInformation(val, valByte)
						self.storeByte(dest, valByte)
						val = val.Extract(val.sz-1, 8)
					else:
						self.storeByte(dest, val)
				else:
					valByte = ADT(val.val & 0xFF)
					copyInformation(val, valByte)
					self.storeByte(dest, valByte)
					val.val = val.val >> 8
				size -= 8
				dest += 1

	def printRegisters(self):
		assert self.gm is not None

		print('Registers')
		for r in config.ARCH.registers:
			val = self.load(r, noneIsFine=True)
			if val is None:
				print(r, None)
			elif val.isSym:
				print(r, '<sym>')
			else:
				print(r, hex(val.val))

		for r in self.segmentRegs:
			if not self.inMem(r):
				continue
			val = self.load(r, noneIsFine=True)
			if type(val) != TLSAccess:
				if val is None:
					print(r, None)
				elif val.isSym:
					print(r, '<sym>')
				else:
					print(r, hex(val.val))
			else:
				print(r, 'tlsAccess')

	def printFlags(self):
		print('Flags')
		for f in self.flags:
			val = self.load(f, noneIsFine=True)
			if val is None:
				print(f, None)
			elif val.isSym:
				print(f, '<sym>')
			else:
				print(f, hex(val.val))

	def printMemory(self, all=False):
		self.printRegisters()
		self.printFlags()
		if all:
			exclude = config.ARCH.registers + self.flags + self.segmentRegs
			assert self.gm is not None
			#FIXME - stack of memories
			#self.gm.printMemory()

	def push(self, val):
		sp = self.load(config.ARCH.spReg)
		sp2 = ADT(sp.val - config.ARCH.size//8)
		copyInformation(sp, sp2)
		sp = sp2
		self.store(config.ARCH.spReg, sp)
		self.store(sp.val, ADT(val))

	def pop(self):
		esp = self.load(config.ARCH.spReg)
		val = self.load(esp.val)
		self.store(config.ARCH.spReg, esp+ADT(config.ARCH.size//8))
		return val

	def tlsLoad(self, addr, size):
		if addr in self.tlsM:
			return self.tlsM[addr]

		ip = self.getIP()
		if config.ARCH == config.x86:
			return u32(self.concrete.read_tls(ip, addr, size))
		else:
			return u64(self.concrete.read_tls(ip, addr, size))
		
	def tlsStore(self, addr, val):
		if self.writable:
			self.tlsM[addr] = val

	def addBT(self, funcName, offset):
		if self.bt:
			if self.bt[-1] == funcName:
				self.bt2.pop()
				self.bt2.append('{}+{}'.format(funcName, int(offset,16)))
				return 

		#Ignore double recursion etc
		if funcName not in self.bt:
			self.bt.append(funcName)
			offset = int(offset, 16)
			if offset != 0:
				self.bt2.append('{}+{}'.format(funcName, offset))
			else:
				self.bt2.append(funcName)

		else:
			i = self.bt.index(funcName)
			self.bt = self.bt[:i+1]
			self.bt2 = self.bt2[:i+1]

	def printBT(self):
		res = 'Backtrace: '
		for f in self.bt2:
			res += f
			if f != self.bt2[-1]:
				res += ' -> '

		print(res)


class GlobalMemory:
	''' Our APG will have a global memory that stores every byte. Parent memories will push to this stack,
			and after all their children execute, the stack from the parent will be popped.
			Each memory will hold a reference to the global memory and in order to load something, it will
			start from the last stack all the way to the first '''

	def __init__(self):
		#Stack of dictionaries. Each element of the stack represent a different memory.
		#Each dictionary is a mapping between addresses and values (ints/bitvecs)
		self.stack = []

		#This will hold information that helps this GM now when to pop a stack
		self.popData = []

		self.current = -1
		self.mems = [] #Memories added to the stack (for optimization reasons)
		self.solver = Solver()
		self.z3Mem = None

		self.auxUID = 0
		
		self.allocatedRanges = []
		self.allocatedRangesMeta = []

		#Keys are auxiliar sym vars. Values are the list of inp sym vars that it depends on
		self.mapAuxToConcrete = {} 

		self.symVars = []
		self.popSymVarsData = []
		self.symVarsMeta = [] #Metadata about how to match symvars with concrete vars in tests
		self.popSymVarsMetaData = []

	def addRestr(self, restr):
		self.solver.add(restr)

	def genAuxSymName(self):
		self.auxUID += 1
		return str(self.auxUID)

	def registerZ3Mem(self, mem):
		if self.z3Mem == mem or (self.mems != [] and self.mems[-1] == mem):
			return

		#If there was another memory previously registered, then it must have finished
			#executing, otherwise this new mem wouldnt be trying to register, so pop the z3 stack
			#to ignore all the changes made by the previous memory
		if self.z3Mem != None:
			self.solver.pop()

		self.solver.push()
		self.z3Mem = mem

	def addSymMetaData(self, tpl):
		self.symVarsMeta.append(tpl)

	def push(self, mem, size):
		if self.mems == [] or mem != self.mems[-1]:
			mem.gm = self
			self.stack.append(mem.m) #Flush contents of memory to the stack
			self.popData.append(size)
			self.current += 1
			self.mems.append(mem)
			self.solver.push()
			self.popSymVarsData.append(len(self.symVars)) #To know how many symvars to discard when this memory pops out
			self.popSymVarsMetaData.append(len(self.symVarsMeta))
			self.allocatedRangesMeta.append(len(self.allocatedRanges))

	def check(self, size):
		while self.popData != []:
			val = self.popData.pop()
			if val < size:
				self.popData.append(val)
				break

			sizeSym = self.popSymVarsData.pop()
			sizeSymMeta = self.popSymVarsMetaData.pop()
			sizeAllocatedRanges = self.allocatedRangesMeta.pop()
			self.symVars = self.symVars[:sizeSym]
			self.symVarsMeta = self.symVarsMeta[:sizeSymMeta]
			self.allocatedRanges = self.allocatedRanges[:sizeAllocatedRanges]
			self.stack.pop()
			self.mems.pop()
			self.solver.pop()
			self.current -= 1
			if self.z3Mem != None:
				self.z3Mem = None
				self.solver.pop()


	def delete(self, name):
		assert self.current >= 0
		self.stack[self.current].pop(name)

	def inMem(self, addr):
		for cur in range(self.current,-1,-1):
			if addr in self.stack[cur]:
				return True
		return False

	def getFromMem(self, addr):
		for cur in range(self.current, -1, -1):
			if addr in self.stack[cur]:
				val = self.stack[cur][addr]
				#Loads are our bottleneck. Act as if this was a cache. This has very significant performance impact
				self.stack[self.current][addr] = val.copy() 
				return val
		return None

	def getFromBaseMem(self, addr):
		if addr in self.stack[0]:
			return self.stack[0][addr]
		else:
			return ADT(0x0)

	def storeInMem(self, addr, val):
		assert self.current >= 0
		self.stack[self.current][addr] = val

	def isItPossible(self, restr):
		self.solver.push()
		self.solver.add(restr)
		possible = self.solver.check() == sat
		self.solver.pop()
		return possible


	def printMemory(self, exclude):
		glob = {} #Global memory

		for i in range(self.current):
			for k in self.m[i]:
				glob[k] = self.m[i][k]

		k = glob.keys()
		rest = [i for i in k if i not in exclude]

		print('Variables')
		for i in rest:
			if type(i) == str:
				print(i,'-->',hex(glob[i].val))
					
		rest = [i for i in rest if type(i) == int]
		rest.sort()

		for i in rest:
			print(hex(i),'-->',hex(glob[i].val))
