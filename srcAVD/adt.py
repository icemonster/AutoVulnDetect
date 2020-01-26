from srcAVD.utils import *
from z3 import *

def copyInformation(source, dest):
	dest.tainted1 = dest.tainted1 or source.tainted1

def propagateInformation(method):
	''' Propagates metadata between two objects acoording to predefined rules '''

	def new_method(self, other):
		obj = method(self, other)
		copyInformation(self, obj)
		copyInformation(other, obj)

		return obj

	return new_method

def conserveInformation(method):
	''' Conserves metadata between between two instances of the same object '''

	def new_method(*args, **kwargs):
		obj = method(*args, **kwargs)
		copyInformation(args[0], obj)
		return obj

	return new_method


class ADT:
	def __init__(self, val):
		self.val = val
		self.isSymbolic = None
		self.size = None
		self.tainted1 = False #Wheter it is some secret that we dont want to leak

	@property
	def sz(self):
		#Only used for symbolic values
		#if self.size is None:
		#	self.size = self.val.size()
		#return self.size
		return self.val.size()

	@property
	def isSym(self):
		#if self.isSymbolic is None: #Faster to keep track of it then calling isSymbolic everytime
		#	self.isSymbolic = isSymbolic(self.val)
		#return self.isSymbolic
		return isSymbolic(self.val)
	
	#Basic binary operations
	@propagateInformation
	def __add__(self, other):
		return ADT(self.val + other.val)

	@propagateInformation
	def __and__(self, other):
		if isinstance(other, ADT):
			return ADT(self.val & other.val)
		else:
			return ADT(self.val & other)

	@propagateInformation
	def __sub__(self, other):
		return ADT(self.val - other.val)

	@propagateInformation
	def __or__(self, other):
		return ADT(self.val | other.val)

	@propagateInformation
	def __mul__(self, other):
		return ADT(self.val * other.val)

	@propagateInformation
	def __lshift__(self, other):
		return ADT(self.val << other.val)

	@propagateInformation
	def __rshift__(self, other):
		return ADT(self.val >> other.val)

	@propagateInformation
	def __xor__(self, other):
		return ADT(self.val ^ other.val)

	@propagateInformation
	def __mod__(self, other):
		return ADT(self.val % other.val)

	@propagateInformation
	def __floordiv__(self, other):
		return ADT(self.val // other.val)

	@propagateInformation
	def __truediv__(self, other):
		return ADT(self.val / other.val)

	@propagateInformation
	def __pow__(self, other):
		return ADT(self.val ** other.val)

	@propagateInformation
	def UDiv(self, other):
		return ADT(UDiv(self.val, other.val))

	@propagateInformation
	def URem(self, other):
		return ADT(URem(self.val, other.val))

	@propagateInformation
	def LShR(self, other):
		return ADT(LShR(self.val, other.val))

	@propagateInformation
	def Concat(self, other):
		return ADT(Concat(self.val, other.val))

	@conserveInformation
	def Extract(self, begin, end):
		return ADT(Extract(begin, end, self.val))

	@conserveInformation
	def copy(self):
		return ADT(self.val)
	#Unary operations
	@conserveInformation
	def twoComplement(self, size=32):
		return ADT(twoComplement(self.val, size))

	@conserveInformation
	def ZeroExt(self, toExtend):
		return ADT(ZeroExt(toExtend, self.val))

	@conserveInformation
	def SignExt(self, toExtend):
		return ADT(SignExt(toExtend, self.val))

	@conserveInformation
	def URem(self, toExtend):
		return ADT(URem(self.val, toExtend.val))

	@conserveInformation
	def __neg__(self):
		return ADT(-self.val)

	@conserveInformation
	def __abs__(self):
		return ADT(abs(self.val))

	@conserveInformation
	def __invert__(self):
		return ADT(~self.val)

	def __repr__(self):
		s =  str(self.val)
		if not self.isSym and self.val < 256:
			s += ' ({})'.format(repr(chr(self.val)))
		return s


class TLSAccess:
	def __init__(self, addr):
		self.addr = addr
		self.isSym = False
	def __add__(self, offset):
		''' Accesses to thread local storage '''
		#No problem in creating new objects every add. There should be only one add for each TLS Access
		return TLSAccess(self.addr + offset.val) 
	#There shouldnt be any more operations
	def __and__(self, mod):
		return TLSAccess(self.addr & mod)
	def __sub__(self, other):
		assert 1 == 0
	def __or__(self, other):
		assert 1 == 0
	def __mul__(self, other):
		assert 1 == 0
	def __lshift__(self, other):
		assert 1 == 0
	def __rshift__(self, other):
		assert 1 == 0
	def __xor__(self, other):
		assert 1 == 0
	def __invert__(self, other):
		assert 1 == 0
	def __mod__(self, other):
		assert 1 == 0
	def __floordiv__(self, other):
		assert 1 == 0
	def __truediv__(self, other):
		assert 1 == 0
	def __pow__(self, other):
		assert 1 == 0
	def twoComplement(self, size=32):
		return TLSAccess(twoComplement(self.addr, size))
	def copy(self):
		return TLSAccess(self.addr)
		
a = ADT(3)
#a.tainted = True

b = ADT(4)

c = a+b

#print('a:', a, a.tainted)
#print('b:', b, b.tainted)
#print('c:', c)#, c.tainted)