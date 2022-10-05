
from typing import Optional
from .base import instr, lm32_gpr
from .pseudo_instructions import instr_nop, instr_mvi

from .utils import as_signed

class instr_add(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RR
		self.populate_operands()

	def instruction_llil(self, il):
		lhs_expr = il.reg(4, lm32_gpr[self.rY])
		rhs_expr = il.reg(4, lm32_gpr[self.rZ])
		sum_expr = il.set_reg(4, lm32_gpr[self.rX], il.add(4, lhs_expr, rhs_expr))
		return sum_expr

class instr_addi(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()

	def instruction_llil(self, il):
		lhs_expr = il.reg(4, lm32_gpr[self.rY])
		rhs_expr = il.const(4, as_signed(self.imm, 16))
		sum_expr = il.set_reg(4, lm32_gpr[self.rX], il.add(4, lhs_expr, rhs_expr))
		return sum_expr

	@property
	def alias(self):
		if self.rX == 0 and self.rY == 0 and self.imm == 0:
			return instr_nop(self.data, self.addr)
		elif self.rY == 0:
			return instr_mvi(self.data, self.addr)

class instr_mul(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RR
		self.populate_operands()

	def instruction_llil(self, il):
		lhs_expr = il.reg(4, lm32_gpr[self.rY])
		rhs_expr = il.reg(4, lm32_gpr[self.rZ])
		mul_expr = il.set_reg(4, lm32_gpr[self.rX], il.mult(4, lhs_expr, rhs_expr))
		return mul_expr

class instr_muli(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()

	def instruction_llil(self, il):
		lhs_expr = il.reg(4, lm32_gpr[self.rY])
		rhs_expr = il.const(4, as_signed(self.imm, 16))
		sum_expr = il.set_reg(4, lm32_gpr[self.rX], il.mult(4, lhs_expr, rhs_expr))
		return sum_expr

class instr_sub(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RR
		self.populate_operands()

	def instruction_llil(self, il):
		lhs_expr = il.reg(4, lm32_gpr[self.rY])
		rhs_expr = il.reg(4, lm32_gpr[self.rZ])
		sum_expr = il.set_reg(4, lm32_gpr[self.rX], il.sub(4, lhs_expr, rhs_expr))
		return sum_expr