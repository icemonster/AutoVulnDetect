from srcAVD.utils import *
from srcAVD.summaries import *
from srcAVD import config
from srcAVD.adt import *
import bap

#FIXME
_summary = Summary('useful summary for safety policies') #Useful to get arguments and stuff. Maybe hackish?

#Safety policies --------------------------------------------------------------
def arbitraryWrite1(code, executor, mem):
	val = executor.computeExp(code.value)
	dest = executor.computeExp(code.idx)

	#Special case. User can decide the size to pass to malloc
	if 'malloc' in mem.bt:
		print('Val:',val.val)
		print('Dest:',dest.val)
		return

	if dest.isSym and val.isSym:
		foundVuln('[!] Arbitrary write detected. User can write his own controlled input wherever he wants', mem)
		return 1


def arbitraryWrite2(code, executor, mem):
	val = executor.computeExp(code.value)
	dest = executor.computeExp(code.idx)

	#Special case. User can decide the size to pass to malloc
	if 'malloc' in mem.bt:
		return

	if dest.isSym:
		foundVuln('[!] Arbitrary write detected. User can write {} wherever he wants'.format(hex(val.val)), mem)
		return 1

def arbitraryRead(code, executor, mem):
	toLoad = code.idx
	val = executor.computeExp(toLoad)

	if val.isSym:
		foundVuln("[!] Arbitrary read detected", mem)
		return 1

def checkPercent(mem, string):
	''' Checks if any of the symbolic values of the string given as argument can contain a "%" '''
	for i in string:
		if isSymbolic(i) and mem.isItPossible(i == ord('%')):
			return True
	return False

def checkFormatString(code, executor, mem):
	formatString = _summary.loadArgs(mem, [str])[0]

	#In order to be exploitable, a format string must be at least 2 chars... %s for instance
	if len(formatString) > 2 and any(map(isSymbolic, formatString)) and checkPercent(mem, formatString):
		foundVuln('[!] Format string vulnerability found. Format string: {}'.format(formatString), mem)
		return 1

def checkFormatStringSN(code, executor, mem):
	s, size, formatString = _summary.loadArgs(mem, [str, int, str])

	#In order to be exploitable, a format string must be at least 2 chars... %s for instance
	if len(formatString) > 2 and any(map(isSymbolic, formatString)) and checkPercent(mem, formatString):
		foundVuln('[!] Format string vulnerability found. Format string: {}'.format(formatString), mem)
		return 1

def checkFormatStringSL(code, executor, mem):
	priority, formatString = _summary.loadArgs(mem, [int, str])

	#In order to be exploitable, a format string must be at least 2 chars... %s for instance
	if len(formatString) > 2 and any(map(isSymbolic, formatString)) and checkPercent(mem, formatString):
		foundVuln('[!] Format string vulnerability found. Format string: {}'.format(formatString), mem)
		return 1


#Exploits ------------------------------------------------------------
CHANGE_VAR_WITH_ADDR = 0x0
CHANGE_VAR_TO = 0x1

#FIXME - move this to config
CAN_PRINT_STR = "STT{"
#CAN_PRINT_STR = "YOU WIN!"

def userControlledJmp(code, executor, mem):
	val = executor.computeExp(code.arg)

	if val.isSym:
		foundExploit("[!] User can change the control flow of the program")
		return 1

def retAddrOverflow(code, executor, mem):
	''' If there is an overflow on the return address, 
		check if we can jump to a specific location '''
	val = executor.computeExp(code.arg)

	if val.isSym: #Indirect jmp
		#If the IP can have the value we specified
		if mem.isItPossible(val.val == config.RETADDROF):
			mem.addRestr(val.val == config.RETADDROF)
			foundExploit('[!] Found exploit to overflow return address with a specific value', mem)
		else:
			if config.EXEC_EXPLOITS:
				foundExploit('Jmp depends on user input!', mem)

def canChangeVar(code, executor, mem):
	val = executor.computeExp(code.value)
	dest = executor.computeExp(code.idx)

	if dest.val == CHANGE_VAR_WITH_ADDR or dest.isSym:
		if val == CHANGE_VAR_TO or val.isSym:
			restr = None
			if dest.isSym and val.isSym:
				restr = And(dest.val == CHANGE_VAR_WITH_ADDR, val.val == CHANGE_VAR_TO)
			elif dest.isSym:
				restr = dest.val == CHANGE_VAR_WITH_ADDR
			elif isSymbolic(val):
				restr = val.val == CHANGE_VAR_TO

			if restr and mem.isItPossible(restr):
				mem.addRestr(restr)
				foundExploit('[!] Found exploit to change variable value', mem)

def canChangeLocalArg(code, executor, mem):
	val = executor.computeExp(code.value)
	dest = executor.computeExp(code.idx)
	rbp = mem.load(config.ARCH.bpReg).val

	if dest.val == rbp-0xc or dest.isSym:
		if val.val == CHANGE_VAR_TO or val.isSym:
		
			restr = None
			if dest.isSym and val.isSym:
				restr = And(dest.val == rbp-0xc, val.val == CHANGE_VAR_TO)
			elif dest.isSym:
				restr = dest.val == rbp-0xc
			elif val.isSym:
				restr = val.val == CHANGE_VAR_TO

			if restr and mem.isItPossible(restr):
				mem.addRestr(restr)
				foundExploit('[!] Found exploit to change local argument value', mem)

def canPrintString(code, executor, mem):
	if config.ARCH == config.x86:
		firstArg = mem.load(config.ARCH.spReg).val + 4
	else:
		firstArg = 'RDI'
		
	toPrint = mem.load(firstArg).val

	res = getString(mem, toPrint)

	if not any(map(isSymbolic, res)):

		#FIXME
		if CAN_PRINT_STR in res:
			assert mem.gm.solver.check() == sat, "Unsatisfiable memory found..." #This should not happen
			foundExploit("There is a way to print '{}'".format(CAN_PRINT_STR), mem)

#----------------------------------------------------------------------------

def runSafetyPolicies(code, executor, mem):
	tCode = type(code)

	toExecute = []
	
	#We dont want to change memory while we are running safety policies
	oldVal = mem.writable
	mem.writable = False 

	if tCode in exploits and config.EXEC_EXPLOITS:
		toExecute += exploits[tCode]
	if tCode in safetyPolicies and config.EXEC_SAFETY_POLICIES:
		toExecute += safetyPolicies[tCode]

	for sp in toExecute:
		if not config.VULN_FOUND and sp(code, executor, mem):
			print('[-] One of the safety policies has failed. Please fix your code!')

	#oldVal might not be True here. We might be running a safety policy inside another one :)
	#	Avoiding nasty bugs since 1996
	mem.writable = oldVal

def foundExploit(exploitStr, mem=None):
	config.VULN_FOUND = True
	config.TERMINATED = True

	print(exploitStr)
	if mem is not None:
		string = concrete_input(mem, minimized=False)
		print('Exploiting input:', string)
		saveExploit(string)

def foundVuln(vunlnStr, mem=None):
	if not config.VULN_FOUND:
		config.VULN_FOUND = True
		config.TERMINATED = True
		print(vunlnStr)

		if mem is not None:
			print('[!] Current IP: {}'.format(hex(mem.getIP())))
			mem.printBT()

		logOnProfile(vunlnStr)

#Keys are types (like <bap.Jmp> or <Summary>)
#Values are list of safety policies
#Safety policies are functions that take the executor, the current code and the memory as input 
	#and check for security conditions and patch accordingly
safetyPolicies = {}
#safetyPolicies[bap.bil.Jmp] = [userControlledJmp]
#safetyPolicies[bap.bil.Load] = [arbitraryRead]
#safetyPolicies[bap.bil.Store] = [arbitraryWrite1, arbitraryWrite2]
safetyPolicies[libcPrintf] = [checkFormatString]
safetyPolicies[libcSnprintf] = [checkFormatStringSN]

exploits = {}
exploits[bap.bil.Jmp] = [retAddrOverflow]
#exploits[bap.bil.Store] = [canChangeLocalArg]
#exploits[libcPuts] = [canPrintString]



