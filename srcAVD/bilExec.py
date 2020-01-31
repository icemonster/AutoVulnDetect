from srcAVD.safetyPolicies import *
from srcAVD.summaries import *
from srcAVD.utils import *
from bap.bil import * 
from srcAVD.adt import ADT, TLSAccess
from pwn import u32, p32
import logging
import bap
from z3 import *

class BilExec(bap.bil.Visitor):
	''' Computes expressions in bil
			All methods return True to stop computation-
			Loads from memories always return ADTs and store's should also store ADTs 

		#Missing enter_In, enter_Out, enter_Both and enter_While '''
		
	def __init__(self, mem, prog):
		self.prog = prog
		self.remainingCode = None
		self.reset(mem)

	def reset(self, mem):
		self.mem = mem
		self.result = None	 #Last result
		self.lastSize = None #Useful to know size of last computed subexpression
		self.new_mems = []

	def getNewMems(self):
		toReturn = self.new_mems
		self.new_mems = []
		return toReturn

	def computeExp(self, exp, nullIsFine=False):
		if exp == ():
			return None

		assert type(exp) != tuple

		runSafetyPolicies(exp, self, self.mem)
		if config.VULN_FOUND:
			return None

		self.run(exp)

		if not nullIsFine and self.result == None and not isinstance(exp, bap.bil.Jmp):
			print('ERROR - result for', exp,' is NULL')
			print('This should never happen!')
			terminate()
			
		res = self.result

		if res is not None and res.isSym:
			res.val = simplify(res.val) #Simplify after computing expression...

		if config.LOGGING: #If logging is enabled...
			if res is not None and type(res.val) == int:
				toDebug = str(exp) + ' --> ' + hex(res.val)
				logging.debug(toDebug)

			elif res is not None:
				toDebug = str(exp) + ' --> ' + str(res.val) #This takes a lot of time for large symbols
				logging.debug(toDebug)
				
		self.result = None #RESET result in case we want to reuse the instance
		return res

	def enter_Var(self, arg):	
		if arg.name == "mem":
			return True

		if type(arg.type) != Imm:
			print('TODO - enter_var. type is not Imm')
			print('This should never happen!')
			terminate()

		name = arg.name
		val = self.mem.load(name, size=arg.type.size)
		if type(val) != TLSAccess: #FIXME - maybe isTLSAccess should be a field of adt
			if val.isSym and val.sz < arg.type.size:
				toExtend = arg.type.size - val.sz
				val = val.ZeroExt(toExtend)

		self.result = val.twoComplement(arg.type.size)
		self.lastSize = arg.type.size
		return True

	def enter_Int(self, arg):	
		self.result = ADT(twoComplement(arg.value, arg.size))
		self.lastSize = arg.size
		return True

	def enter_Load(self, arg):
		toLoad = arg.idx
		val = self.computeExp(toLoad)

		if type(val) == TLSAccess:
			self.result = ADT(self.mem.tlsLoad(val.addr, arg.size))
		else:
			val = self.mem.load(val.val, size=arg.size)
			self.result = val.twoComplement(arg.size)

		self.lastSize = arg.size
		return True

	def enter_Store(self, arg):	
		size = arg.size

		val = self.computeExp(arg.value)
		dest = self.computeExp(arg.idx)

		if type(dest) == TLSAccess:
			self.mem.tlsStore(dest.addr, val)
		else:
			self.mem.store(dest.val, val, size=size)

		self.result = None
		self.lastSize = None
		return True

	def enter_Move(self, arg):
		name = arg.var.name

		if name == "mem": #We handle memory our own way
			self.computeExp(arg.expr, nullIsFine=True)
			self.result = None
			return True

		size = arg.var.type.size 
		val = self.computeExp(arg.expr)

		self.mem.store(name, val, size)

		self.result = None
		self.lastSize = None
		return True

	def enter_Jmp(self, arg):
		val = self.computeExp(arg.arg)

		assert not val.isSym, "Indirect jumps still not completely supported"

		self.mem.setIP(val.val)
		self.mem.jumped = True #Needed when jumping to same instruction
		self.result = None
		self.lastSize = None
		return True

	def enter_Special(self, arg):
		''' syscalls go here '''
		
		if arg.arg == 'Unknown Semantics':
			print("I found something that could not be lifted. Maybe floating point operations")
			self.mem.hlt = True
		elif arg.arg == "int 0x80":
			if 'syscall' in summaries:
				code = summaries['syscall']
				code.execute(self, self.mem)
		elif arg.arg == "lock":
			pass #No multi threaded programs here
		else:
			self.TODO("Special operation", arg)

		return True

	def enter_If(self, arg):
		cond = self.computeExp(arg.cond)
		assert cond.val == 1 or cond.val == 0 or cond.isSym

		if cond.val == 1:
			if type(arg.true) == tuple:
				for statement in arg.true:
					self.run(statement)
			else:
					self.run(arg.true)
		elif cond.val == 0:
			if type(arg.false) == tuple:
				for statement in arg.false:
					self.run(statement)
			else:
				self.run(arg.false)
		else:
			canBeTrue = self.mem.isItPossible(cond.val == True)
			canBeFalse = self.mem.isItPossible(cond.val == False)

			#If condition can be both true and false
			if canBeTrue and canBeFalse:
				
				self.mem.executedIf = True
				if self.remainingCode is not None:
					if type(self.remainingCode) != tuple:
						self.remainingCode = (self.remainingCode,)

				#Make a copy of the memory
				mem1 = self.mem.copy()
				mem1.nextRestr.append(cond.val == True)
				mem1.nextFunc = arg.true

				if type(mem1.nextFunc) != tuple:
					mem1.nextFunc = (mem1.nextFunc, )
				
				if self.remainingCode is not None:
					mem1.nextFunc = mem1.nextFunc + self.remainingCode

				self.new_mems.append(mem1)

				mem2 = self.mem.copy()
				mem2.nextRestr.append(cond.val == False)
				mem2.nextFunc = arg.false

				if type(mem2.nextFunc) != tuple:
					mem2.nextFunc = (mem2.nextFunc, )
				if self.remainingCode is not None:
					mem2.nextFunc = mem2.nextFunc + self.remainingCode
				
				self.new_mems.append(mem2)


			elif canBeTrue: #If condition can only be true
				self.mem.addRestr(cond.val == True) #Add restriction to solver
				self.run(arg.true)

			elif canBeFalse: #If condition can only be false
				self.mem.addRestr(cond.val == False) #Add restriction to solver
				self.run(arg.false)
				
		return True

	def enter_CpuExn(self, arg):
		print("CPU Exception occured on one of the memories. Maybe div by 0")
		print(arg)
		self.mem.hlt = True
		self.result = ADT(0x0)
		return True

	#Binary Operations
	def enter_PLUS(self, arg):
		lhs = self.computeExp(arg.lhs)
		rhs = self.computeExp(arg.rhs)
		result = lhs + rhs
		self.result = result.twoComplement(self.lastSize)
		return True

	def enter_MINUS(self, arg):
		lhs = self.computeExp(arg.lhs)
		rhs = self.computeExp(arg.rhs)
		rhs = -rhs
		rhs = rhs.twoComplement(self.lastSize) #Compute 2-complement of negative
		result = lhs + rhs
		self.result = result.twoComplement(self.lastSize) #Add lhs to 2-complement of rhs
		return True

	def enter_TIMES(self, arg):
		lhs = self.computeExp(arg.lhs)
		rhs = self.computeExp(arg.rhs)
		result = lhs * rhs
		self.result = result.twoComplement(self.lastSize)
		return True

	def enter_SDIVIDE(self, arg):
		lhs = self.computeExp(arg.lhs)
		lhsSize = self.lastSize
		rhs = self.computeExp(arg.rhs)
		rhsSize = self.lastSize
		negative = False

		if not lhs.isSym:
			if bitIsSet(lhs.val, lhsSize-1): #If MSB bit is set <=> number is negative
				negative = not negative
				lhs = -lhs 
				lhs = lhs.twoComplement(lhsSize)

		if not rhs.isSym:
			if bitIsSet(rhs.val, rhsSize-1): #If 32th bit is set <=> number is negative
				negative = not negative
				rhs = -rhs 
				rhs = rhs.twoComplement(rhsSize)
		
		if lhs.isSym or rhs.isSym:
			val = lhs / rhs  #Z3 bitvec integer division is '/'
		else:
			val = lhs // rhs

		if negative:
			val = -val

		self.result = val.twoComplement(lhsSize)	
		self.lastSize = lhsSize
		return True

	def enter_DIVIDE(self, arg):
		lhs = self.computeExp(arg.lhs)
		lhsSize = self.lastSize
		rhs = self.computeExp(arg.rhs)

		if lhs.isSym or rhs.isSym:
			self.result = lhs.UDiv(rhs)
		else:
			result = lhs // rhs 
			self.result = result.twoComplement(lhsSize)

		self.lastSize = lhsSize
		return True

	def enter_MOD(self, arg):
		lhs = self.computeExp(arg.lhs)
		lhsSize = self.lastSize
		rhs = self.computeExp(arg.rhs)

		if lhs.isSym or rhs.isSym:
			self.result = lhs.URem(rhs)
		else:
			result = lhs % rhs
			self.result = result.twoComplement(lhsSize)

		self.lastSize = lhsSize
		return True

	def enter_SMOD(self, arg):
		
		lhs = self.computeExp(arg.lhs)
		lhsSize = self.lastSize
		rhs = self.computeExp(arg.rhs)
		rhsSize = self.lastSize

		if not lhs.isSym:
			if bitIsSet(lhs.val, lhsSize-1): #If 32th bit is set <=> number is negative
				lhs = -lhs 
				lhs = lhs.twoComplement(lhsSize)
				lhs = -lhs #Get real value from two complement negative

		if not rhs.isSym:
			if bitIsSet(rhs.val, rhsSize-1): #If 32th bit is set <=> number is negative
				rhs = -rhs 
				rhs = rhs.twoComplement(rhsSize)
				rhs = -rhs #Get real value from two complement negative

		result = lhs % rhs
		self.result = result.twoComplement(lhsSize)
		self.lastSize = lhsSize
		return True

	def enter_LSHIFT(self, arg):
		lhs = self.computeExp(arg.lhs)
		lhsSize = self.lastSize
		rhs = self.computeExp(arg.rhs)

		result = lhs << rhs
		self.result = result.twoComplement(lhsSize)
		self.lastSize = lhsSize
		return True

	def enter_RSHIFT(self, arg):
		lhs = self.computeExp(arg.lhs)
		lhsSize = self.lastSize #Second argument might be a 2-bit number for all we know :)
		rhs = self.computeExp(arg.rhs)

		result = lhs >> rhs
		self.result = result.twoComplement(lhsSize)
		self.lastSize = lhsSize
		return True

	def enter_ARSHIFT(self, arg):
		
		lhs = self.computeExp(arg.lhs)
		lhsSize = self.lastSize
		rhs = self.computeExp(arg.rhs)

		if lhs.isSym or rhs.isSym:
			self.result = lhs.LShR(rhs)
		else:
			self.result = lhs.copy()
			for i in range(rhs.val):
				self.result = (self.result >> ADT(1))
				if bitIsSet(lhs.val, lhsSize-1):
					self.result = ADT(pow(2,lhsSize-1)) + self.result
			self.result = self.result.twoComplement(lhsSize)

		self.lastSize = lhsSize
		return True

	def enter_AND(self, arg):
		
		lhs = self.computeExp(arg.lhs)
		rhs = self.computeExp(arg.rhs)
		result = lhs & rhs
		self.result = result.twoComplement(self.lastSize)
		return True

	def enter_OR(self, arg):
		
		lhs = self.computeExp(arg.lhs)
		rhs = self.computeExp(arg.rhs)
		result = lhs | rhs
		self.result = result.twoComplement(self.lastSize)
		return True

	def enter_XOR(self, arg):

		lhs = self.computeExp(arg.lhs)
		rhs = self.computeExp(arg.rhs)
		result = lhs ^ rhs
		self.result = result.twoComplement(self.lastSize)
		return True

	def enter_EQ(self, arg):
		
		lhs = self.computeExp(arg.lhs)
		rhs = self.computeExp(arg.rhs)
		if lhs.isSym or rhs.isSym:
			self.result = ADT(If(lhs.val == rhs.val, BitVecVal(1, 1), BitVecVal(0, 1)))
		else:
			self.result = ADT(lhs.val == rhs.val)

		copyInformation(lhs, self.result)
		copyInformation(rhs, self.result)

		return True

	def enter_NEQ(self, arg):
		
		lhs = self.computeExp(arg.lhs)
		rhs = self.computeExp(arg.rhs)

		if lhs.isSym or rhs.isSym:
			self.result = ADT(If(lhs.val != rhs.val, BitVecVal(1, 1), BitVecVal(0, 1)))
		else:
			self.result = ADT(lhs.val != rhs.val)

		copyInformation(lhs, self.result)
		copyInformation(rhs, self.result)

		return True

	def enter_LT(self, arg):
		
		lhs = self.computeExp(arg.lhs)
		rhs = self.computeExp(arg.rhs)

		if lhs.isSym or rhs.isSym:
			self.result = ADT(If(ULT(lhs.val, rhs.val), BitVecVal(1, 1), BitVecVal(0, 1)))
		else:
			self.result = ADT(lhs.val < rhs.val)

		copyInformation(lhs, self.result)
		copyInformation(rhs, self.result)

		return True

	def enter_LE(self, arg):
		
		lhs = self.computeExp(arg.lhs)
		rhs = self.computeExp(arg.rhs)

		if lhs.isSym or rhs.isSym:
			self.result = ADT(If(ULE(lhs.val, rhs.val), BitVecVal(1, 1), BitVecVal(0, 1)))
		else:
			self.result = ADT(lhs.val <= rhs.val)

		copyInformation(lhs, self.result)
		copyInformation(rhs, self.result)

		return True

	def enter_SLT(self, arg):
		
		lhs = self.computeExp(arg.lhs)
		lhsSize = self.lastSize
		rhs = self.computeExp(arg.rhs)
		rhsSize = self.lastSize


		if not lhs.isSym:
			if bitIsSet(lhs.val, lhsSize-1): #If 32th bit is set <=> number is negative
				lhs = -lhs 
				lhs = lhs.twoComplement(lhsSize)
				lhs = -lhs #Get real value from two complement negative

		if not rhs.isSym:
			if bitIsSet(rhs.val, rhsSize-1): #If 32th bit is set <=> number is negative
				rhs = -rhs 
				rhs = rhs.twoComplement(rhsSize)
				rhs = -rhs #Get real value from two complement negative

		if lhs.isSym or rhs.isSym:
			self.result = ADT(If(lhs.val < rhs.val, BitVecVal(1, 1), BitVecVal(0, 1)))
		else:
			self.result = ADT(lhs.val < rhs.val)

		copyInformation(lhs, self.result)
		copyInformation(rhs, self.result)

		return True

	def enter_SLE(self, arg):
		
		lhs = self.computeExp(arg.lhs)
		lhsSize = self.lastSize
		rhs = self.computeExp(arg.rhs)
		rhsSize = self.lastSize

		if not lhs.isSym:
			if bitIsSet(lhs.val, lhsSize-1): #If 32th bit is set <=> number is negative
				lhs = -lhs 
				lhs = lhs.twoComplement(lhsSize)
				lhs = -lhs #Get real value from two complement negative

		if not rhs.isSym:
			if bitIsSet(rhs.val, rhsSize-1): #If 32th bit is set <=> number is negative
				rhs = -rhs 
				rhs = rhs.twoComplement(rhsSize)
				rhs = -rhs #Get real value from two complement negative

		if lhs.isSym or rhs.isSym:
			self.result = ADT(If(lhs.val <= rhs.val, BitVecVal(1, 1), BitVecVal(0, 1)))
		else:
			self.result = ADT(lhs.val <= rhs.val)

		copyInformation(lhs, self.result)
		copyInformation(rhs, self.result)

		return True

	#Unary operations
	def enter_NEG(self, arg): #2-s complement
		val = self.computeExp(arg.arg)
		result = -val
		self.result = result.twoComplement(self.lastSize)
		return True

	def enter_NOT(self, arg): #1-s complement	
		val = self.computeExp(arg.arg)
		result = ~val
		self.result = result.twoComplement(self.lastSize)
		return True 

	def enter_UNSIGNED(self, arg):
		afterSize = arg.size
		val = self.computeExp(arg.expr)
		beforeSize = self.lastSize

		if val.isSym:
			self.result = val.ZeroExt(afterSize-beforeSize)
		else:
			#Extending with zeroes is the same as doing nothing, with python integers...
			self.result = val
		
		self.lastSize = afterSize
		return True

	def enter_SIGNED(self, arg):
		afterSize = arg.size
		val = self.computeExp(arg.expr)
		beforeSize = self.lastSize

		if val.isSym:
			self.result = val.SignExt(afterSize-beforeSize)
		else:
			val2 = bin(val.val)[2:].zfill(beforeSize)
			if val2[0] == '1': #If MSB is 1, extend with 1's
				extend = '1'*(afterSize-beforeSize) #How many bits to extend
			else:
				extend = '0'*(afterSize-beforeSize)

			result = int(extend + val2, 2)
			self.result = ADT(twoComplement(result, afterSize))
			copyInformation(val, self.result)

		self.lastSize = afterSize
		return True

	def enter_HIGH(self, arg):
		val = self.computeExp(arg.expr)
		size = self.lastSize

		if val.isSym:
			self.result = val.Extract(size-1, size-arg.size)
		else:
			bits = '1'*arg.size
			bits = bits + '0'*(size-arg.size)
			mask = int(bits, 2)
			self.result = ADT(twoComplement((val.val & mask) >> (size-arg.size), arg.size))
			copyInformation(val, self.result)

		self.lastSize = arg.size
		return True

	def enter_LOW(self, arg):	
		val = self.computeExp(arg.expr)
		
		if val.isSym:
			self.result = val.Extract(arg.size-1, 0)
		else:
			bits = '1'*arg.size
			self.result = ADT(twoComplement(val.val & int(bits, 2), arg.size))
		
		copyInformation(val, self.result)
		self.lastSize = arg.size
		return True

	def enter_Let(self, arg):
		#Let this variable
		var = arg.var.name

		#Have this value
		val = self.computeExp(arg.value)
		sz = self.lastSize
		oldVal = self.mem.load(var, size=sz, noneIsFine=True)
		self.mem.store(var, val, size=sz)

		#In this expression
		res = self.computeExp(arg.expr)

		#And not in the other expressions of course :D
		if oldVal is None:
			self.mem.delete(var)
		else:
			self.mem.store(var, oldVal, size=sz)

		self.result = res 
		return True

	def enter_Unknown(self, arg):
		self.result = ADT(0x0) #UNKNOWN IS 0x0, everyone knows that
		return True

	#These just never appeared... maybe BAP IL doesnt use them
	def TODO(self, msg, arg):
		print('TODO: {}'.format(msg))
		print(arg)
		print(dir(arg))
		terminate()
	def enter_In(self, arg):
	    self.TODO('In', arg)
	def enter_Out(self, arg):
	    self.TODO('Out', arg)
	def enter_Both(self, arg):
	    self.TODO('Both', arg)

	def enter_While(self, arg):
		''' FIXME: Account for symbolic condition. Probably should modify "code" 
			and unroll one iteration of the loop each time we execute it '''
		while self.computeExp(arg.cond).val:
			for statement in arg.stmts:
				self.run(statement)
		return True

	def enter_Ite(self, arg):
		cond = self.computeExp(arg.cond)
		assert cond.val == 1 or cond.val == 0 or cond.isSym

		if cond.val == 1:
			self.result = self.computeExp(arg.true)
		elif cond.val == 0:
			self.result = self.computeExp(arg.false)
		else:
			canBeTrue = self.mem.isItPossible(cond.val == True)
			canBeFalse = self.mem.isItPossible(cond.val == False)
			
			assert canBeTrue or canBeFalse #I mean, it has to be one of them...

			if canBeTrue and canBeFalse:
				name = 'ite_{}'.format(self.mem.genSymName()) #Generate unique name for symbolic var
				
				val1 = self.computeExp(arg.true)
				val2 = self.computeExp(arg.false)
				var = BitVec(name, self.lastSize)

				self.mem.addRestr(Or(And(cond.val == True, var == val1.val), And(cond == False, var == val2.val)))
				self.result = ADT(var)
			elif canBeTrue: #If condition can only be true
				self.mem.addRestr(cond.val == True)
				self.result = self.computeExp(arg.true)
			elif canBeFalse: #If condition can only be false
				self.mem.addRestr(cond.val == False) #Add restriction to solver
				self.result = self.computeExp(arg.false)

		return True

	def enter_Extract(self, arg):
		hb = arg.high_bit
		lb = arg.low_bit

		val = self.computeExp(arg.expr)
		size = self.lastSize

		#https://github.com/BinaryAnalysisPlatform/bap/blob/master/lib/bap/bap.mli#L2299
		if hb > size-1:
			hb = size-1
		if lb < 0:
			lb = 0

		if val.isSym:
			self.result = val.Extract(hb, lb)
		else:
			val2 = bin(val.val)[2:].zfill(size)
			val2 = val2[::-1] #Invert bits so its easier to return result (hb - lb converts to lb - hb)

			result = val2[lb:hb+1] #Inclusive the last
			result = result[::-1] #Invert again
			self.result = ADT(twoComplement(int(result,2), hb-lb+1))

		copyInformation(val, self.result)
		self.lastSize = hb-lb+1 #size of result is how many bits we've taken from expression value
		return True

	def enter_Concat(self, arg):
		lhs = self.computeExp(arg.lhs)
		sizeLhs = self.lastSize
		rhs = self.computeExp(arg.rhs)
		sizeRhs = self.lastSize

		if lhs.isSym or rhs.isSym:
			if not lhs.isSym:
				lhs.val = BitVecVal(lhs.val, sizeLhs)
			if not rhs.isSym:
				rhs.val = BitVecVal(rhs.val, sizeRhs)
			self.result = lhs.Concat(rhs)
		else:
			rhs2 = bin(rhs.val)[2:].zfill(sizeRhs)
			lhs2 = bin(lhs.val)[2:].zfill(sizeLhs)
			self.result = ADT(int(lhs2+rhs2,2)) #Join them together and take the integer value
			copyInformation(lhs, self.result)
			copyInformation(rhs, self.result)
		
		self.lastSize = sizeLhs + sizeRhs
		return True

