import binaryninja
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken, InstructionTextTokenType
from binaryninja.enums import BranchType

import struct
import typing

from .base import instr, lm32_gpr


class instr_mv(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RR
		self.populate_operands()

	def instruction_text(self):
		return [
			InstructionTextToken(InstructionTextTokenType.TextToken, '%-6s' % self.mnemonic),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rX]),
			InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rY])
		]

	def instruction_llil(self, il):
		src = il.reg(4, self.rY)
		return il.set_reg(4, lm32_gpr[self.rX], src)

class instr_mvi(instr):
	def __init__(self, data: int, addr: int, value_hint: typing.Optional[int]=None):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()
		if value_hint is not None:
			self.imm = value_hint

	def instruction_text(self):
		return [
			InstructionTextToken(InstructionTextTokenType.TextToken, '%-6s' % self.mnemonic),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rX]),
			InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
			InstructionTextToken(InstructionTextTokenType.IntegerToken, '%d' % self.imm, self.imm)
		]

	def instruction_llil(self, il):
		val = il.const(4, self.imm)
		expr = il.set_reg(4, lm32_gpr[self.rX], val)
		return expr

class instr_nop(instr):
	def __call__(self, data, addr):
		super().__init__(data, addr)
	
	def instruction_text(self):
		return [
			InstructionTextToken(InstructionTextTokenType.TextToken, '%s' % self.mnemonic)
		]
	
	def instruction_llil(self, il):
		return il.nop()

class instr_ret(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)

	def instruction_text(self):
		return [
			InstructionTextToken(InstructionTextTokenType.TextToken, '%s' % self.mnemonic)
		]

	def instruction_llil(self, il):
		return il.ret(il.reg(4, 'ra'))

	def branching_info(self):
		return [(BranchType.FunctionReturn, )]

class instr_TODO(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)

	def instruction_text(self):
		op2mnem = {0: 'srui', 1: 'nori', 2: 'muli', 3: 'sh', 4: 'lb', 5: 'sri', 6: 'xori', 7: 'lh', 8: 'andi', 9: 'xnori', 10: 'lw', 11: 'lhu', 12: 'sb', 13: 'addi', 14: 'ori', 15: 'sli', 16: 'lbu', 17: 'be', 18: 'bg', 19: 'bge', 20: 'bgeu', 21: 'bgu', 22: 'sw', 23: 'bne', 24: 'andhi', 25: 'cmpei', 26: 'cmpgi', 27: 'cmpgei', 28: 'cmpgeui', 29: 'cmpgui', 30: 'orhi', 31: 'cmpnei', 32: 'sru', 33: 'nor', 34: 'mul', 35: 'divu', 36: 'rcsr', 37: 'sr', 38: 'xor', 39: 'div', 40: 'and', 41: 'xnor', 42: 'reserved', 43: 'raise', 44: 'sextb', 45: 'add', 46: 'or', 47: 'sl', 48: 'b', 49: 'modu', 50: 'sub', 51: 'reserved', 52: 'wcsr', 53: 'mod', 54: 'call', 55: 'sexth', 56: 'bi', 57: 'cmpe', 58: 'cmpg', 59: 'cmpge', 60: 'cmpgeu', 61: 'cmpgu', 62: 'calli', 63: 'cmpne', 64: 'TODO'}
		try:
			return [InstructionTextToken(InstructionTextTokenType.TextToken, 'TODO: %s' % (op2mnem[self.opcode], ))]
		except Exception as e:
			return [InstructionTextToken(InstructionTextTokenType.TextToken, 'ERROR: %s' % e)]

	def instruction_llil(self, il):
		return il.nop()
	