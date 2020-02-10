#toBeautify = raw_input("To prettify: ")
toBeautify = '''(Move(Var("#45",Imm(64)),SIGNED(64,Load(Var("mem",Mem(64,8)),PLUS(Var("RBP",Imm(64)),Int(18446744073709551608,64)),LittleEndian(),32))), Move(Var("#44",Imm(64)),Concat(LOW(32,Var("RDX",Imm(64))),LOW(32,Var("RAX",Imm(64))))), If(EQ(Var("#45",Imm(64)),Int(0,64)), (CpuExn(0)), (Move(Var("#46",Imm(64)),SDIVIDE(Var("#44",Imm(64)),Var("#45",Imm(64)))), Move(Var("#47",Imm(64)),SMOD(Var("#44",Imm(64)),Var("#45",Imm(64)))), If(OR(SLT(Int(9223372036854775807,64),Var("#46",Imm(64))),SLT(Var("#46",Imm(64)),Int(9223372036854775808,64))), (CpuExn(0)), (Move(Var("#48",Imm(64)),Concat(LOW(32,Var("#47",Imm(64))),LOW(32,Var("#46",Imm(64))))), Move(Var("RAX",Imm(64)),UNSIGNED(64,Extract(31,0,Var("#48",Imm(64))))), Move(Var("RDX",Imm(64)),UNSIGNED(64,Extract(63,32,Var("#48",Imm(64))))))))), Move(Var("CF",Imm(1)),Unknown("bits",Imm(1))), Move(Var("OF",Imm(1)),Unknown("bits",Imm(1))), Move(Var("SF",Imm(1)),Unknown("bits",Imm(1))), Move(Var("ZF",Imm(1)),Unknown("bits",Imm(1))), Move(Var("AF",Imm(1)),Unknown("bits",Imm(1))), Move(Var("PF",Imm(1)),Unknown("bits",Imm(1))))'''

res = ''

''' Could be more beautiful... Could be uglier '''
depth = 0
for i in range(0, len(toBeautify)):

	res += toBeautify[i]

	if toBeautify[i] == '(':
		depth += 1
		res += '\n' + '\t'*depth
	elif toBeautify[i] == ')':
		depth -= 1
		res += '\n' + '\t'*depth


print res