import binaryninja
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken, InstructionTextTokenType
from binaryninja.enums import BranchType

import struct


def as_signed(val, bits):
	sign_mask   = 1 << (bits -1)
	value_mask  = sign_mask - 1
	return (val & value_mask) - (val & sign_mask)

# general purpose registers
LM32_GPR = [
	'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8',
	'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16',
	'r17', 'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24',
	'r25', 'gp', 'fp', 'sp', 'ra', 'ea', 'ba'
]


class Operand(object):
	REG = 0
	IMM = 1
	MEM = 2
	REL = 3

	def __init__(self, operand_type, rshift, shifted_mask):
		self.operand_type = operand_type
		self.rshift = rshift
		self.shifted_mask = shifted_mask

	def extract(self, raw_value):
		return (raw_value >> self.rshift) & self.shifted_mask


class Instr(object):
	fmt_RRR = (Operand(Operand.REG, 21, 0x1F), Operand(Operand.REG, 16, 0x1F), Operand(Operand.REG, 11, 0x1F)) # r_src1, r_src2, r_dst
	fmt_RRI = (Operand(Operand.REG, 21, 0x1F), Operand(Operand.REG, 16, 0x1F), Operand(Operand.IMM, 0, 0xFFFF)) # r_src1, r_dst, i_src2
	fmt_bRRI = (Operand(Operand.REG, 21, 0x1F), Operand(Operand.REG, 16, 0x1F), Operand(Operand.IMM, 0, 0xFFFF)) # r_src1, r_src2, i_src3
	fmt_R = (Operand(Operand.REG, 21 , 0x1F), ) # r_src
	fmt_I = (Operand(Operand.REL, 0, 0x3ffffff), ) # i_src
	fmt_RNR = (Operand(Operand.REG, 21, 0x1F), Operand(Operand.REG, 11, 0x1F)) # r_src, None, r_dst
	fmt_RRNI = (Operand(Operand.REG, 21, 0x1F), Operand(Operand.REG, 16, 0x1F), Operand(Operand.IMM, 0, 0xF)) # r_src, r_dst, None, i_src
	fmt_Empty = tuple()

	def __init__(self, raw, opcode, addr, mnemonic, fmt, is_branching=False):
		self.raw = raw
		self.opcode = opcode
		self.addr = addr
		self.mnemonic = mnemonic
		self.fmt = fmt
		self.is_branching = is_branching


	def extract_branching_info(self):
		if self.mnemonic == 'bi':
			(off, ) = self.extract_operands()
			return BranchType.UnconditionalBranch, self.addr + as_signed(off << 2, 18)

		elif self.mnemonic == 'b':
			(src_reg1, ) = self.extract_operands()
			if src_reg1 == 29: # b ra / ret
				return (BranchType.FunctionReturn, )
			else:
				return (BranchType.IndirectBranch, )
		
		elif self.mnemonic in ['be', 'bne', 'bg', 'bgu', 'bge', 'bgeu']:
			_, _, off = self.extract_operands()
			return [
				(BranchType.TrueBranch, self.addr + as_signed(off << 2, 18)),
				(BranchType.FalseBranch, self.addr + 4)
			]
		
		elif self.mnemonic == 'calli':
			(off, ) = self.extract_operands()
			return BranchType.CallDestination, self.addr + as_signed(off << 2, 28)

		elif self.mnemonic == 'call':
			return (BranchType.IndirectBranch, )

		# else:
			# print("TODO: extract_branching_info for %s" % self.mnemonic)

	def extract_operands(self):
		# TODO: figure out how to handle cases when len(extract_operands()) == 1, thus we can't extract values correctly
		return [op.extract(self.raw) for op in self.fmt]


	def as_tokens(self):
		res = [InstructionTextToken(InstructionTextTokenType.TextToken, '%-6s' % self.mnemonic)]
		if self.fmt == self.fmt_RRR:
			src_reg1, src_reg2, dst_reg = self.extract_operands()
			res.extend([
				InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % LM32_GPR[dst_reg]),
				InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
				InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % LM32_GPR[src_reg1]),
				InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
				InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % LM32_GPR[src_reg2])
			])
		elif self.fmt == self.fmt_RRI:
			src_reg, dst_reg, src_imm = self.extract_operands()
			res.extend([
				InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % LM32_GPR[dst_reg]),
				InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
				InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % LM32_GPR[src_reg]),
				InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
				InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, '%#x' % src_imm, 16)
			])
		elif self.fmt == self.fmt_R:
			(src_reg, ) = self.extract_operands()
			res.extend([
				InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % LM32_GPR[src_reg])
			])
		elif self.fmt == self.fmt_I:
			(src_imm, ) = self.extract_operands()
			res.extend([
				InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, '%#x' % (self.addr + as_signed(src_imm << 2, 28))) # long jump/call
			])
		elif self.fmt == self.fmt_bRRI:
			src_reg1, src_reg2, src_imm = self.extract_operands()
			res.extend([
				InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % LM32_GPR[src_reg2]),
				InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
				InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % LM32_GPR[src_reg1]),
				InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
				InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, '%#x' % (self.addr + as_signed(src_imm << 2, 18))) # short jump/call
			])
		return res



def decode_instruction(data, addr):
	instructions = (
		("srui", Instr.fmt_RRI),
		("nori", Instr.fmt_RRI),
		("muli", Instr.fmt_RRI),
		("sh", Instr.fmt_RRI),
		("lb", Instr.fmt_RRI),
		("sri", Instr.fmt_RRNI),
		("xori", Instr.fmt_RRI),
		("lh", Instr.fmt_RRI),
		("andi", Instr.fmt_RRI),
		("xnori", Instr.fmt_RRI),
		("lw", Instr.fmt_RRI),
		("lhu", Instr.fmt_RRI),
		("sb", Instr.fmt_RRI),
		("addi", Instr.fmt_RRI),
		("ori", Instr.fmt_RRI),
		("sli", Instr.fmt_RRNI),
		("lbu", Instr.fmt_RRI),
		("be", Instr.fmt_bRRI, True),
		("bg", Instr.fmt_bRRI, True),
		("bge", Instr.fmt_bRRI, True),
		("bgeu", Instr.fmt_bRRI, True),
		("bgu", Instr.fmt_bRRI, True),
		("sw", Instr.fmt_RRI),
		("bne", Instr.fmt_bRRI, True),
		("andhi", Instr.fmt_RRI),
		("cmpei", Instr.fmt_RRI),
		("cmpgi", Instr.fmt_RRI),
		("cmpgei", Instr.fmt_RRI),
		("cmpgeui", Instr.fmt_RRI),
		("cmpgui", Instr.fmt_RRI),
		("orhi", Instr.fmt_RRI),
		("cmpnei", Instr.fmt_RRI),
		("sru", Instr.fmt_RRR),
		("nor", Instr.fmt_RRR),
		("mul", Instr.fmt_RRR),
		("divu", Instr.fmt_RRR),
		("rcsr", ),
		("sr", Instr.fmt_RRR),
		("xor", Instr.fmt_RRR),
		("div", ), # TODO: idk, there is no description in official reference
		("and", Instr.fmt_RRR),
		("xnor", Instr.fmt_RRR),
		("reserved", ),
		("raise", ),
		("sextb", Instr.fmt_RNR),
		("add", Instr.fmt_RRR),
		("or", Instr.fmt_RRR),
		("sl", Instr.fmt_RRR),
		("b", Instr.fmt_R, True),
		("modu", Instr.fmt_RRR),
		("sub", Instr.fmt_RRR),
		("reserved", ),
		("wcsr", ),
		("mod", ), # TODO: idk, there is no description in official reference
		("call", Instr.fmt_R, True),
		("sexth", Instr.fmt_RNR),
		("bi", Instr.fmt_I, True),
		("cmpe", Instr.fmt_RRR),
		("cmpg", Instr.fmt_RRR),
		("cmpge", Instr.fmt_RRR),
		("cmpgeu", Instr.fmt_RRR),
		("cmpgu", Instr.fmt_RRR),
		("calli", Instr.fmt_I, True),
		("cmpne", Instr.fmt_RRR),

		("TODO", Instr.fmt_Empty)
	)

	try:
		raw = struct.unpack('>I', data)[0]
	except struct.error as e:
		return None

	opcode = (raw >> 26) & 0x3F
	
	try:
		result = Instr(raw, opcode, addr, *instructions[opcode])
	except TypeError as e:
		# print(e)
		# print(*instructions[opcode])
		result = Instr(raw, len(instructions)-1, addr, *instructions[len(instructions)-1])

	return result


class Lm32(Architecture):
	name = 'Lattice Mico32'

	endianness = binaryninja.enums.Endianness.BigEndian

	# address_size = 4
	# default_int_size = 4
	# instr_alignment = 4
	# max_instr_length = 4

	# general purpose registers
	regs = {i:RegisterInfo(i, 4) for i in LM32_GPR}

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

		insn = decode_instruction(data, addr)
		if insn is None:
			return None

		if insn.is_branching:   
			branching_info = insn.extract_branching_info()
			if type(branching_info) is list:
				for i in branching_info:
					info.add_branch(*i)
			elif branching_info is not None:
				info.add_branch(*branching_info)

		return info


	def get_instruction_text(self, data, addr):
		if len(data) < 4:
			return (), 0

		instr = decode_instruction(data[:4], addr)
		if instr is None:
			print('None at %#x with %s' % (addr, repr(data)))
		return instr.as_tokens(), 4


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