from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken, InstructionTextTokenType

from .utils import as_signed, token

lm32_gpr = (
	'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8',
	'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16',
	'r17', 'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24',
	'r25', 'gp', 'fp', 'sp', 'ra', 'ea', 'ba'
)

LM32_REG2NUM = { v:i for i,v in enumerate(lm32_gpr) }

class Op:
	def __init__(self, rshift, mask):
		self.rshift = rshift
		self.mask = mask

	def extract(self, raw):
		return (raw >> self.rshift) & self.mask

class InstructionFormat:
	def __init__(self, *ops):
		self.ops = ops

	def extract_operands(self, raw):
		return [op.extract(raw) for op in self.ops]

class instr:
	
	fmt_RI = InstructionFormat(Op(21, 0x1F), Op(16, 0x1F), Op(0, 0xFFFF))
	fmt_RR = InstructionFormat(Op(21, 0x1F), Op(16, 0x1F), Op(11, 0x1F))
	fmt_CR = InstructionFormat(Op(21, 0x1F), Op(16, 0x1F))
	fmt_I  = InstructionFormat(Op(0, 0x3ffffff))

	# op2mnem = {0: 'srui', 1: 'nori', 2: 'muli', 3: 'sh', 4: 'lb', 5: 'sri', 6: 'xori', 7: 'lh', 8: 'andi', 9: 'xnori', 10: 'lw', 11: 'lhu', 12: 'sb', 13: 'addi', 14: 'ori', 15: 'sli', 16: 'lbu', 17: 'be', 18: 'bg', 19: 'bge', 20: 'bgeu', 21: 'bgu', 22: 'sw', 23: 'bne', 24: 'andhi', 25: 'cmpei', 26: 'cmpgi', 27: 'cmpgei', 28: 'cmpgeui', 29: 'cmpgui', 30: 'orhi', 31: 'cmpnei', 32: 'sru', 33: 'nor', 34: 'mul', 35: 'divu', 36: 'rcsr', 37: 'sr', 38: 'xor', 39: 'div', 40: 'and', 41: 'xnor', 42: 'reserved', 43: 'raise', 44: 'sextb', 45: 'add', 46: 'or', 47: 'sl', 48: 'b', 49: 'modu', 50: 'sub', 51: 'reserved', 52: 'wcsr', 53: 'mod', 54: 'call', 55: 'sexth', 56: 'bi', 57: 'cmpe', 58: 'cmpg', 59: 'cmpge', 60: 'cmpgeu', 61: 'cmpgu', 62: 'calli', 63: 'cmpne', 64: 'TODO'}

	def __init__(self, data: int, addr: int):
		self.addr = addr
		self.data = data
		self.opcode = (data >> 26) & 0x3F
		self.format = None

	def instruction_text(self):
		res = token.mnem(self.mnemonic)
		if self.format == self.fmt_RR:
			res.extend([
				InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rX]),
				InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
				InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rY]),
				InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
				InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rZ])
			])
		elif self.format == self.fmt_RI:
			res.extend([
				InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rX]),
				InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
				InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rY]),
				InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
				InstructionTextToken(InstructionTextTokenType.IntegerToken, '%d' % as_signed(self.imm, 16), self.imm, size=2)
			])
		elif self.format == self.fmt_CR:
			raise NotImplementedError
		elif self.format == self.fmt_I:
			res.extend([
				InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, '%#x' % (self.addr + as_signed(self.imm << 2, 28)), self.addr + as_signed(self.imm << 2, 28), size=4)
			])
		else:
			raise ValueError("Unknown instruction format: %s" % self.format)
		
		return res

	def branching_info(self):
		pass

	def instruction_llil(self, il):
		return il.nop()

	def populate_operands(self):
		if self.format == self.fmt_RR:
			self.rY, self.rZ, self.rX = self.format.extract_operands(self.data)
		elif self.format == self.fmt_RI:
			self.rY, self.rX, self.imm = self.format.extract_operands(self.data)
		elif self.format == self.fmt_CR:
			raise NotImplementedError
		elif self.format == self.fmt_I:
			self.imm, = self.format.extract_operands(self.data)
		else:
			raise ValueError("Unknown instruction format: %s" % self.format)

	@property
	def alias(self):
		pass

	@property
	def mnemonic(self):
		return self.__class__.__name__.replace('instr_', '')
