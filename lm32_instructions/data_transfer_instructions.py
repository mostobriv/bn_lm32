import binaryninja
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken, InstructionTextTokenType
from binaryninja.enums import BranchType

from .base import instr, lm32_gpr
from .utils import as_signed, token

class memory_load_instr:
	def instruction_text(self):
		res = token.mnem(self.mnemonic)
		res.extend([
			token.reg(self.rX),
			InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
			InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, '('),
			token.reg(self.rY),
			token.plus(),
			InstructionTextToken(InstructionTextTokenType.IntegerToken, '%d' % as_signed(self.imm, 16), self.imm, size=2),
			InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ')')
		])

		return res

class memory_store_instr:
	def instruction_text(self):
		res = token.mnem(self.mnemonic)
		res.extend([
			InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, '('),
			token.reg(self.rX),
			token.plus(),
			InstructionTextToken(InstructionTextTokenType.IntegerToken, '%d' % as_signed(self.imm, 16), self.imm, size=2),
			InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ')'),
			InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
			token.reg(self.rY),
		])

		return res

class instr_lbu(memory_load_instr, instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()

	def instruction_llil(self, il):
		addr_displ_reg_expr = il.reg(4, lm32_gpr[self.rY])
		addr_displ_imm_expr = il.const(4, as_signed(self.imm, 16))
		address_expr = il.add(4, addr_displ_reg_expr, addr_displ_imm_expr)
		loaded_value_expr = il.zero_extend(4, il.load(1, address_expr))
		return il.set_reg(4, lm32_gpr[self.rX], loaded_value_expr)

class instr_lhu(memory_load_instr, instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()

	def instruction_llil(self, il):
		addr_displ_reg_expr = il.reg(4, lm32_gpr[self.rY])
		addr_displ_imm_expr = il.const(4, as_signed(self.imm, 16))
		address_expr = il.add(4, addr_displ_reg_expr, addr_displ_imm_expr)
		loaded_value_expr = il.zero_extend(4, il.load(2, address_expr))
		return il.set_reg(4, lm32_gpr[self.rX], loaded_value_expr)
	

class instr_sb(memory_store_instr, instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()
		self.rX, self.rY = self.rY, self.rX

	def instruction_llil(self, il):
		addr_displ_reg_expr = il.reg(4, lm32_gpr[self.rX])
		addr_displ_imm_expr = il.const(4, as_signed(self.imm, 16))
		address_expr = il.add(4, addr_displ_reg_expr, addr_displ_imm_expr)
		storing_value_expr = il.reg(1, lm32_gpr[self.rY])
		return il.store(1, address_expr, storing_value_expr)


class instr_lw(memory_load_instr, instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()

	def instruction_llil(self, il):
		addr_displ_reg_expr = il.reg(4, lm32_gpr[self.rY])
		addr_displ_imm_expr = il.const(4, as_signed(self.imm, 16))
		address_expr = il.add(4, addr_displ_reg_expr, addr_displ_imm_expr)
		loaded_value_expr = il.load(4, address_expr)
		return il.set_reg(4, lm32_gpr[self.rX], loaded_value_expr)

class instr_sw(memory_store_instr, instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()
		self.rX, self.rY = self.rY, self.rX

	def instruction_llil(self, il):
		addr_displ_reg_expr = il.reg(4, lm32_gpr[self.rX])
		addr_displ_imm_expr = il.const(4, as_signed(self.imm, 16))
		address_expr = il.add(4, addr_displ_reg_expr, addr_displ_imm_expr)
		storing_value_expr = il.reg(4, lm32_gpr[self.rY])
		return il.store(4, address_expr, storing_value_expr)