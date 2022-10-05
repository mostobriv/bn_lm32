from binaryninja.function import InstructionTextToken, InstructionTextTokenType

def mnem(mnemonic):
	res = [InstructionTextToken(InstructionTextTokenType.InstructionToken, '%s' % mnemonic)]
	res.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' ' * (6 - len(mnemonic))))
	return res

def reg(reg):
	regs = ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24', 'r25', 'gp', 'fp', 'sp', 'ra', 'ea', 'ba')
	return InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % regs[reg])

def sign(num):
	if num >= 0:
		return InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, '+')
	else:
		return InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, '-')

def plus():
	return InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, '+')
