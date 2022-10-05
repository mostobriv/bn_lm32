
from .base import instr, lm32_gpr
from .pseudo_instructions import instr_mv, instr_mvi

from .utils.il import get_reg

class instr_and(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RR
		self.populate_operands()

	def instruction_llil(self, il):
		lhs_expr = lhs_expr = get_reg(self.rY, il)
		rhs_expr = lhs_expr = get_reg(self.rZ, il)
		and_expr = il.and_expr(4, lhs_expr, rhs_expr)
		return il.set_reg(4, lm32_gpr[self.rX], and_expr)

class instr_andi(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()

	def instruction_llil(self, il):
		lhs_expr = lhs_expr = get_reg(self.rY, il)
		rhs_expr = il.const(4, self.imm)
		and_expr = il.and_expr(4, lhs_expr, rhs_expr)
		return il.set_reg(4, lm32_gpr[self.rX], and_expr)

class instr_xor(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RR
		self.populate_operands()

	def instruction_llil(self, il):
		lhs_expr = lhs_expr = get_reg(self.rY, il)
		rhs_expr = lhs_expr = get_reg(self.rZ, il)
		xor_expr = il.xor_expr(4, lhs_expr, rhs_expr)
		return il.set_reg(4, lm32_gpr[self.rX], xor_expr)

class instr_xori(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()

	def instruction_llil(self, il):
		lhs_expr = lhs_expr = get_reg(self.rY, il)
		rhs_expr = il.zero_extend(4, il.const(2, self.imm))
		xor_expr = il.xor_expr(4, lhs_expr, rhs_expr)
		return il.set_reg(4, lm32_gpr[self.rX], xor_expr)

class instr_or(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RR
		self.populate_operands()

	def instruction_llil(self, il):
		lhs_expr = lhs_expr = get_reg(self.rY, il)
		rhs_expr = lhs_expr = get_reg(self.rZ, il)
		or_expr = il.or_expr(4, lhs_expr, rhs_expr)
		return il.set_reg(4, lm32_gpr[self.rX], or_expr)

	@property
	def alias(self):
		if self.rZ == 0:
			return instr_mv(self.data, self.addr)

class instr_ori(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()

	def instruction_llil(self, il):
		lhs_expr = get_reg(self.rY, il)
		rhs_expr = il.const(4, self.imm)
		or_expr = il.or_expr(4, lhs_expr, rhs_expr)
		return il.set_reg(4, lm32_gpr[self.rX], or_expr)

	@property
	def alias(self):
		if self.rY == 0:
			return instr_mvi(self.data, self.addr)

class instr_orhi(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()

	def instruction_llil(self, il):
		lhs_expr = get_reg(self.rY, il)
		rhs_expr = il.shift_left(4, il.const(4, self.imm), il.const(4, 16))
		or_expr = il.or_expr(4, lhs_expr, rhs_expr)
		return il.set_reg(4, lm32_gpr[self.rX], or_expr)

	@property
	def alias(self):
		if self.rY == 0:
			return instr_mvi(self.data, self.addr, value_hint=(self.imm << 16))