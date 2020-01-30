#!/usr/bin/env python3
import sys
import bap
import os
from srcAVD import config

#8 first because it is more likely to happen
#Yes I care about performance and yes Im using python
hexdigits = ('8012345679abcdef')

def readline(code, i):
	while code[i] != '\n':
		i += 1
	return i

def getAddress(code, i):
	addr = ''
	while code[i] in hexdigits:
		addr += code[i]
		i += 1
	return int(addr,16)

def parse(code):
	stack = []
	res = {}

	code = code.decode()
	tokenOps = {'(':')', '[':']'}

	i = 0
	size = len(code)
	inToken = False
	token = ''
	addr = 0x00000000
	doneToken = False

	perserveThese = set() #Set of addresses where push's and call's happen

	while i < size:
		c = code[i]
		
		#Concerning tokens
		if c in ')]':
			c2 = stack.pop()
			assert c == tokenOps[c2]
			if stack == []: #If stack is now empty
				doneToken = True
		elif c in tokenOps:
			stack.append(c)
			inToken = True
		elif c == '"':
			if stack != [] and stack[-1] == '"':
				assert c == stack.pop()
			else:
				stack.append(c)
		elif not inToken and c in hexdigits:
			#Concerning everything else
			addr = getAddress(code, i)
			j = i
			i = readline(code, i)
			line = code[j:i]
			line = line.split(': ')
			if len(line) == 2:
				if 'push' in line[1] or 'call' in line[1]:
					ip = int(line[0], 16)
					if 'call' in line[1] or '%rip' in line[1] or '%eip' in line[1]:
						perserveThese.update([(ip, 'instruction pointer')])
					elif '%rbp' in line[1] or '%ebp' in line[1]:
						perserveThese.update([(ip, 'base pointer')])
					elif '%' in line[1]:
						perserveThese.update([(ip, 'saved register')])
					else:
						perserveThese.update([(ip, 'immediate value')])

			c = '\n'
		elif code[i:i+20].startswith('Disassembly'):
			i = readline(code, i)
			c = '\n'

		token += c
		if doneToken:
			doneToken = False
			inToken = False
			res[addr] = bap.bil.loads(token)
			token = ''
		i += 1

	return perserveThese, res

def saveAndParse(code):
	with open('{}.bap'.format(config.BINARY_NAME),'wb') as f:
		f.write(code)

	return parse(code)

def isMoreRecent(f1, f2):
	modifF1 = os.path.getmtime(f1)
	modifF2 = os.path.getmtime(f2)
	return modifF1 > modifF2

def parseProj(name):
	res = {}

	bil_adt_project_parser = {'load' : saveAndParse}

	fileName = '{}.bap'.format(name)

	#If we hadn't analyzed that binary before or the binary has changed...
	if not os.path.isfile(fileName) or isMoreRecent(name, fileName):
		if config.ARCH == config.x86:
			toPerserve, proj = bap.run(name, args=["-dbil.adt"], parser=bil_adt_project_parser)
		else:
			toPerserve, proj = bap.run(name, args=["-dbil.adt", "--llvm-base={}".format(hex(config.BASE_ADDR))], parser=bil_adt_project_parser)
	else:
		print('Loading {} ({} was already parsed)'.format(fileName, name))
		with open(fileName,'rb') as f:
			data = f.read()
			toPerserve, proj = parse(data)
	
	ks = list(proj.keys())
	ks.sort()
	
	for ki in range(len(ks)-1):
		res[ks[ki]] = (ks[ki+1]-ks[ki],proj[ks[ki]]) #Compute size of instructions
	
	res[ks[-1]] = (0, proj[ks[-1]])
	return toPerserve, res

if __name__ == "__main__":
	name = sys.argv[1]
	toPerserve, proj = parseProj(name)

	ks = list(proj.keys())
	ks.sort()
	for i in ks:
		print(i, proj[i])