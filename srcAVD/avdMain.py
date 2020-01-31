#!/usr/bin/env python3

import logging
import sys

from srcAVD.utils import *
from srcAVD.summaries import *
from srcAVD.parseBilProg import *
from srcAVD.safetyPolicies import *
from srcAVD.concreteTarget import AvatarGDBConcreteTarget
from srcAVD.program import Program
from srcAVD.bilExec import BilExec
from srcAVD import config
from srcAVD.memory import Memory, GlobalMemory
from code import interact #Debug
import re 
import functools

logger = logging.getLogger()

DESCR_RE = re.compile('\+0x(\w+) ')

class APG:
	def __init__(self, name, debug=True):
		'''
			self.Q : Priority queue of Memory instances
				(Each memory has the value of IP)
		'''
		self.Q = []
		self.Qsize = 0

		progName = os.path.relpath(name).split('/')[-1]
		config.REAL_BINARY_NAME = progName

		print('Analysing {} ({})'.format(progName, config.ARCH.name))

		self.concrete = AvatarGDBConcreteTarget(config.GDB_IP, config.GDB_PORT, name)
		toPerserve, program = parseProj(name)

		self.program = Program(program, self.concrete)
		self.breakpoints = []
		self.step = False
		self.debug = debug

		self.gm = None #Global memory
		self.progName = progName

		self.callsAndPushes = []
		self.setPerserveValues(toPerserve)

	def setPerserveValues(self, values):
		self.callsAndPushes = values
		
	def printDescription(self, mem, ip, descr):
		offset = DESCR_RE.findall(descr)
			
		if offset != []:
			offset = offset[0]
			descr = descr.replace('+0x{}'.format(offset), '+{}'.format(int(offset, 16)))
		if 'PLT.' in descr:
			func = descr.split('+')[0]
			func = func[4:]

			if func not in summaries and not config.STRIPPED_BINARY:
				print(config.ARCH.ipReg,':',hex(ip),'-',descr)
				#FIXME 
				print('You should implement the above summary')
				mem.hlt = True #FIXME
				#terminate()
		if self.debug or self.step:
			if not config.STRIPPED_BINARY:
				print('[{}]{}: '.format(mem.memId, config.ARCH.ipReg),hex(ip),'-',descr, file=sys.stdout)
			else:
				print('[{}]{}: '.format(mem.memId, config.ARCH.ipReg),hex(ip), file=sys.stdout)

	def setBreakpoint(self, addr):
		if addr not in self.breakpoints:
			self.breakpoints.append(addr)
			print('Set breakpoint',len(self.breakpoints),'at',hex(addr))

	def addMemToQueue(self, mem):
		ip = mem.getIP()
		self.Q.append(mem)
		self.Qsize += 1

	def prior(self, parentStatus, mem1, mem2):
		if mem1.getIP() < mem2.getIP():
			return 1
		return -1

	def addMemsToQueue(self, parentStatus, mems):
		''' Adds memories to the global queue accordingly to their priority '''

		if len(mems) == 1:
			return self.addMemToQueue(mems[0])

		mems = sorted(mems, key=functools.cmp_to_key(lambda x,y: self.prior(parentStatus, x, y)))
		for mem in mems:
			self.addMemToQueue(mem)

	def executeCode(self, interpreter, mem, code, putOnQueue=True, oldIP=-1):
		if oldIP == -1:
			oldIP = mem.getIP()

		parentStatus = mem.status.copy()

		if isinstance(code, Summary):
			runSafetyPolicies(code, interpreter, mem)
			if config.VULN_FOUND:
				return

			code.execute(interpreter, mem)
			if not mem.hlt and putOnQueue and interpreter.new_mems == []:
				self.addMemToQueue(mem) #Put the memory back on the queue
		else:
			if type(code) != tuple: #code being a tuple simplifies next loop
				code = (code, )

			i = 0 #Necessary to track the code that was not executed yet
			for c in code:	
				runSafetyPolicies(c, interpreter, mem)
				if config.VULN_FOUND:
					return
				interpreter.remainingCode = code[i+1:]
				interpreter.run(c)
				interpreter.remainingCode = None
				if mem.jumped: #IF a jmp was executed
					if putOnQueue:
						self.addMemToQueue(mem) #Add memory again to continue execution
						mem.addValuesToPerserve(self.callsAndPushes, oldIP)
					break
				elif mem.hlt:
					break
				elif interpreter.new_mems != []:
					break

				i += 1

			#If there were no jumps and memory didnt halt... And memory didn't split...
			if not mem.jumped and not mem.hlt and interpreter.new_mems == [] and mem.nextFunc is None:
				ip = mem.getIP()
				newIp = self.program.getNextInstruction(ip)
				mem.setIP(newIp)
				
				if putOnQueue:
					self.addMemToQueue(mem)
					mem.addValuesToPerserve(self.callsAndPushes, oldIP)
	
		if interpreter.new_mems != []:
			new_mems = interpreter.getNewMems()

			#Tells gm that a pop will be needed when len(self.Q) == the current len
				#(unless this memory is already in execution)
			self.gm.push(mem, self.Qsize) 
			mems = []

			for mem2 in new_mems:
				if mem2.nextFunc is not None:
					interpreter.reset(mem2) #Get interpreter ready for the new memory
					code = mem2.nextFunc
					mem2.nextFunc = None
					self.executeCode(interpreter, mem2, code, putOnQueue=False, oldIP=oldIP)
					
			for mem2 in new_mems:
				if not mem2.hlt: #Dont add unnecessary memories
					mems.append(mem2)

			self.addMemsToQueue(parentStatus, mems)
			for mem in mems:
				mem.addValuesToPerserve(self.callsAndPushes, oldIP)

	def run(self):
		logging.debug("Running")
		logging.debug('-------------------')

		#Instruction pointer is pointing at main
		mem = self.program.concrete.mem
		self.gm = self.program.concrete.gm

		#Single interpreter for all memories
		interpreter = BilExec(mem, self.program)

		self.addMemToQueue(mem)

		main = self.program.concrete.ld.find_symbol('main')

		if main is not None:
			finishLine = main.rebased_addr + main.size - 1
		else:
			finishLine = None

		diverge = 0
		config.VULN_FOUND = False
		config.TERMINATED = False

		#Main loop
		while self.Qsize != 0 and not config.TERMINATED:
			self.gm.check(self.Qsize) #Check if a pop is needed

			mem = self.Q.pop()
			self.Qsize -= 1
			mem.jumped = False

			self.gm.registerZ3Mem(mem)
			for restr in mem.nextRestr:
				mem.addRestr(restr)
			mem.nextRestr = []

			interpreter.reset(mem) #Get interpreter ready for the new memory
			ip = mem.getIP()

			descr = self.program.concrete.ld.describe_addr(ip)

			self.printDescription(mem, ip, descr)

			#FIXME - This should just check if its executable or not
			if 'not part of a loaded object' in descr:
				if not config.STRIPPED_BINARY:
					print('[{}]SEGFAULT - This may be caused by the execution of dynamic code'.format(mem.memId))
				mem.hlt = True
				continue

			#Check if we reach the end of analysis
			if ip == finishLine: #Avoid _fini redefinition and such...
				retAddr = mem.load(config.ARCH.spReg)
				if isSymbolic(retAddr):
					foundVuln("[!] User can change main's return address!!", mem)
				mem.hlt = True
				continue

			if config.LOGGING:
				with open('debugAVD.txt','a+') as f:
					regValues = {}
					for reg in config.ARCH.registers:
						regValues[reg] = hex(mem.getFromMem(reg).val)
					f.write(hex(ip)+'-')
					f.write(str(regValues)+'\n')

			code = self.program.getBlk(ip)
			if code is None:
				mem.hlt = True

			if self.step:
				interact(banner="Step", local=locals(), exitmsg="")
			
			#Check breakpoints before executing
			elif ip in self.breakpoints:
				breakpoint= "Breakpoint {}".format(self.breakpoints.index(ip)+1)
				interact(banner=breakpoint, local=locals(), exitmsg="Resuming execution...")

			self.executeCode(interpreter, mem, code)

			#Have to do this here because when executing concretely, a summary usually ends up
				#in the beginning of the backtrace
			descr = self.program.concrete.ld.describe_addr(mem.getIP())
			fName, offset = get_name_outof_descr(descr)
			mem.addBT(fName, offset)

		self.gm.check(0)

		print('Finished analysis for the current POV.')
		if config.VULN_FOUND:
			print('A vulnerability was found.')
		else:
			print('Nothing was found.')

		logging.debug('-------------------')
		logging.debug('POV done')

		self.concrete.exit()

#echo 0 | sudo tee /proc/sys/kernel/randomize_va_space (disable ASLR)
