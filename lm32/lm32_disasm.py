import binaryninja
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken, InstructionTextTokenType
from binaryninja.enums import BranchType

import collections

LM32_GPREGISTERS = (
	'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8',
	'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16',
	'r17', 'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24',
	'r25', 'gp', 'fp', 'sp', 'ra', 'ea', 'ba'
)

def as_signed(val, bits):
	sign_mask   = 1 << (bits -1)
	value_mask  = sign_mask - 1
	return (val & value_mask) - (val & sign_mask)

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

	def __init__(self, data: int, addr: int):
		self.addr = addr
		self.data = data
		self.opcode = (data >> 24) & 0xFF

	def instruction_text(self, *args, **kwargs):
		raise NotImplementedError('Called abstract `instruction_text` method')

	def instruction_il(self, *args, **kwargs):
		raise NotImplementedError('Called abstract `instruction_il` method')
	
	def resolve_alias(self, *args, **kwargs):
		raise NotImplementedError('Called abstract `resolve_alias` method')


class instr_add(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RR
		self.rY, self.rX, self.Imm = self.format.extract_operands(data)

	def instruction_text(self, *args, **kwargs):
		return ''

	def instruction_il(self, *args, **kwargs):
		return None

class instr_addi(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.rY, self.rX, self.Imm = self.format.extract_operands(data)

	def instruction_text(self):
		return ''


	def instruction_il(self):
		return None

class instr_TODO(instr):
	op2mnem = {0: 'srui', 1: 'nori', 2: 'muli', 3: 'sh', 4: 'lb', 5: 'sri', 6: 'xori', 7: 'lh', 8: 'andi', 9: 'xnori', 10: 'lw', 11: 'lhu', 12: 'sb', 13: 'addi', 14: 'ori', 15: 'sli', 16: 'lbu', 17: 'be', 18: 'bg', 19: 'bge', 20: 'bgeu', 21: 'bgu', 22: 'sw', 23: 'bne', 24: 'andhi', 25: 'cmpei', 26: 'cmpgi', 27: 'cmpgei', 28: 'cmpgeui', 29: 'cmpgui', 30: 'orhi', 31: 'cmpnei', 32: 'sru', 33: 'nor', 34: 'mul', 35: 'divu', 36: 'rcsr', 37: 'sr', 38: 'xor', 39: 'div', 40: 'and', 41: 'xnor', 42: 'reserved', 43: 'raise', 44: 'sextb', 45: 'add', 46: 'or', 47: 'sl', 48: 'b', 49: 'modu', 50: 'sub', 51: 'reserved', 52: 'wcsr', 53: 'mod', 54: 'call', 55: 'sexth', 56: 'bi', 57: 'cmpe', 58: 'cmpg', 59: 'cmpge', 60: 'cmpgeu', 61: 'cmpgu', 62: 'calli', 63: 'cmpne', 64: 'TODO'}
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)

	def instruction_text(self):
		try:
			mnemonic = self.op2mnem[self.opcode]
			return InstructionTextToken(InstructionTextTokenType.TextToken, 'TODO: %s (%#x)' % (mnemonic, ))
		except Exception as e:
			return InstructionTextToken(InstructionTextTokenType.TextToken, 'ERROR: %s' % e)



op2ins = collections.defaultdict(instr_TODO)
op2ins.extend({
	# 0: instr_srui,
	# 1: instr_nori,
	# 2: instr_muli,
	# 3: instr_sh,
	# 4: instr_lb,
	# 5: instr_sri,
	# 6: instr_xori,
	# 7: instr_lh,
	# 8: instr_andi,
	# 9: instr_xnori,
	# 10: instr_lw,
	# 11: instr_lhu,
	# 12: instr_sb,
	13: instr_addi,
	# 14: instr_ori,
	# 15: instr_sli,
	# 16: instr_lbu,
	# 17: instr_be,
	# 18: instr_bg,
	# 19: instr_bge,
	# 20: instr_bgeu,
	# 21: instr_bgu,
	# 22: instr_sw,
	# 23: instr_bne,
	# 24: instr_andhi,
	# 25: instr_cmpei,
	# 26: instr_cmpgi,
	# 27: instr_cmpgei,
	# 28: instr_cmpgeui,
	# 29: instr_cmpgui,
	# 30: instr_orhi,
	# 31: instr_cmpnei,
	# 32: instr_sru,
	# 33: instr_nor,
	# 34: instr_mul,
	# 35: instr_divu,
	# 36: instr_rcsr,
	# 37: instr_sr,
	# 38: instr_xor,
	# 39: instr_div,
	# 40: instr_and,
	# 41: instr_xnor,
	# 42: instr_reserved,
	# 43: instr_raise,
	# 44: instr_sextb,
	45: instr_add,
	# 46: instr_or,
	# 47: instr_sl,
	# 48: instr_b,
	# 49: instr_modu,
	# 50: instr_sub,
	# 51: instr_reserved,
	# 52: instr_wcsr,
	# 53: instr_mod,
	# 54: instr_call,
	# 55: instr_sexth,
	# 56: instr_bi,
	# 57: instr_cmpe,
	# 58: instr_cmpg,
	# 59: instr_cmpge,
	# 60: instr_cmpgeu,
	# 61: instr_cmpgu,
	# 62: instr_calli,
	# 63: instr_cmpne,
})


class Lm32(Architecture):
	name = 'Lattice Mico32'

	endianness = binaryninja.enums.Endianness.BigEndian

	# address_size = 4
	# default_int_size = 4
	# instr_alignment = 4
	# max_instr_length = 4

	# general purpose registers
	regs = {i:RegisterInfo(i, 4) for i in LM32_GPREGISTERS}

	# control status registers
	regs.extend({
		"pc": RegisterInfo("pc", 4), # not indexed
	})

	regs.extend({
		"IE": RegisterInfo("IE", 4), # 0
	})

	stack_pointer = 'sp'

	def get_instruction_info(self, data, addr):
		info = InstructionInfo()
		info.length = 4

		return info

	def get_instruction_text(self, data, addr):
		import struct
		return op2ins[data[0]].instruction_text()

	def get_instruction_low_level_il(self, data, addr, il):
		pass

	@property
	def address_size(self):
		return 4 # 32 bit

	@property
	def default_int_size(self):
		return 4

	@property
	def instr_alignment(self):
		return 4

	@property
	def max_instr_length(self):
		return 4


Lm32.register()

_lm32_arch = binaryninja.architecture.Architecture['Lattice Mico32']

binaryninja.binaryview.BinaryViewType['ELF'].register_arch(
	138, binaryninja.enums.Endianness.BigEndian, _lm32_arch
)