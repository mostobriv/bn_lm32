from .base import instr, lm32_gpr
from .utils import as_signed


class instr_sli(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()

	# def instruction_llil(self, il):
	# 	lhs_expr = il.reg(4, lm32_gpr[self.rY])
	# 	rhs_expr = il.const(4, as_signed(self.imm, 16))
	# 	sum_expr = il.set_reg(4, lm32_gpr[self.rX], il.mult(4, lhs_expr, rhs_expr))
	# 	return sum_expr

class instr_sl(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RR
		self.populate_operands()

	def instruction_llil(self, il):
		lhs_expr = il.reg(4, lm32_gpr[self.rY])
		rhs_expr = il.and_expr(1, il.reg(4, lm32_gpr[self.rZ]), il.const(1, 0x1F))
		shift_expr = il.set_reg(4, lm32_gpr[self.rX], il.shift_left(4, lhs_expr, rhs_expr))
		return shift_expr

class instr_srui(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()

	def instruction_llil(self, il):
		lhs_expr = il.reg(4, lm32_gpr[self.rY])
		rhs_expr = il.const(4, as_signed(self.imm, 16))
		shift_expr = il.set_reg(4, lm32_gpr[self.rX], il.logical_shift_right(4, lhs_expr, rhs_expr))
		return shift_expr