from re import L
import binaryninja
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken, InstructionTextTokenType
from binaryninja.enums import BranchType
from binaryninja.lowlevelil import LowLevelILLabel

from .base import instr, LM32_REG2NUM, lm32_gpr
from .pseudo_instructions import instr_ret
from . import utils
from .utils.il import get_reg

def resolve_il_label_for_address(address, il):
	label = il.get_label_for_address(Architecture["Lattice Mico32"], address)
	if not label:
		il.add_label_for_address(Architecture["Lattice Mico32"], address)
		label = il.get_label_for_address(Architecture["Lattice Mico32"], address)
		assert label is not None
	
	# print("Resolved label for address: %#x" % address)
	return label

def create_if_expr(if_cond_expr, true_address, false_address, il):
	t = il.get_label_for_address(Architecture["Lattice Mico32"], true_address)
	f = il.get_label_for_address(Architecture["Lattice Mico32"], false_address)

	if t and f:
		return il.if_expr(if_cond_expr, t, f)
	
	t = LowLevelILLabel()
	f = LowLevelILLabel()

	il.append(il.if_expr(if_cond_expr, t, f))
	il.mark_label(t)
	il.append(goto_or_jump(true_address, il))
	il.mark_label(f)

	# assert il.get_label_for_address(Architecture["Lattice Mico32"], true_address) == t
	# assert il.get_label_for_address(Architecture["Lattice Mico32"], false_address) == f
	
	
	# il.if_expr(if_cond_expr, t, f)
	return None


def goto_or_jump(address, il):
	tmp = il.get_label_for_address(Architecture["Lattice Mico32"], address)
	if tmp:
		return il.goto(tmp)
	else:
		return il.jump(il.const_pointer(4, address))
	

class instr_b(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RR
		self.populate_operands()
		self.rX = self.rY # exception as in `b` instruction only rX is presented

	def branching_info(self):
		return [(BranchType.IndirectBranch, )]

	def instruction_text(self):
		res = [InstructionTextToken(InstructionTextTokenType.TextToken, '%-6s' % self.mnemonic)]
		res.extend([
			InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rX]),
		])
		return res

	def instruction_llil(self, il):
		jmp_dst = get_reg(self.rX, il)
		return il.jump(jmp_dst)

	@property
	def alias(self):
		if self.rX == LM32_REG2NUM['ra']:
			return instr_ret(self.data, self.addr)

class instr_bi(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_I
		self.populate_operands()

	def branching_info(self):
		return [(BranchType.UnconditionalBranch, self.addr + utils.as_signed(self.imm << 2, 28))]

	def instruction_llil(self, il):
		addr = self.addr + utils.as_signed(self.imm << 2, 28)
		llil_label = il.get_label_for_address(Architecture["Lattice Mico32"], addr)
		if llil_label:
			return il.goto(llil_label)
		else:
			return il.jump(il.const_pointer(4, addr))

class instr_be(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()

	def instruction_text(self):
		res = [InstructionTextToken(InstructionTextTokenType.TextToken, '%-6s' % self.mnemonic)]
		res.extend([
			InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rX]),
			InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rY]),
			InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, '%#x' % (self.addr + utils.as_signed(self.imm << 2, 18)), self.addr + utils.as_signed(self.imm << 2, 18), size=4)
		])
		return res

	def branching_info(self):
		return [
			(BranchType.TrueBranch, self.addr + utils.as_signed(self.imm << 2, 18)),
			(BranchType.FalseBranch, self.addr + 4)
		]

	def instruction_llil(self, il):
		true_addr = self.addr + utils.as_signed(self.imm << 2, 18)
		false_addr = self.addr + 4
		cmp_expr = il.compare_equal(4, get_reg(self.rX, il), get_reg(self.rY, il))
		return create_if_expr(cmp_expr, true_addr, false_addr, il)
	
class instr_bne(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()

	def instruction_text(self):
		res = [InstructionTextToken(InstructionTextTokenType.TextToken, '%-6s' % self.mnemonic)]
		res.extend([
			InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rX]),
			InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rY]),
			InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, '%#x' % (self.addr + utils.as_signed(self.imm << 2, 18)), self.addr + utils.as_signed(self.imm << 2, 18), size=4)
		])
		return res

	def branching_info(self):
		return [
			(BranchType.TrueBranch, self.addr + utils.as_signed(self.imm << 2, 18)),
			(BranchType.FalseBranch, self.addr + 4)
		]

	def instruction_llil(self, il):
		true_addr = self.addr + utils.as_signed(self.imm << 2, 18)
		false_addr = self.addr + 4
		cmp_expr = il.compare_not_equal(4, get_reg(self.rX, il), get_reg(self.rY, il))
		return create_if_expr(cmp_expr, true_addr, false_addr, il)

class instr_bgu(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()

	def instruction_text(self):
		res = [InstructionTextToken(InstructionTextTokenType.TextToken, '%-6s' % self.mnemonic)]
		res.extend([
			InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rX]),
			InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rY]),
			InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, '%#x' % (self.addr + utils.as_signed(self.imm << 2, 18)), self.addr + utils.as_signed(self.imm << 2, 18), size=4)
		])
		return res

	def branching_info(self):
		return [
			(BranchType.TrueBranch, self.addr + utils.as_signed(self.imm << 2, 18)),
			(BranchType.FalseBranch, self.addr + 4)
		]

	def instruction_llil(self, il):
		true_addr = self.addr + utils.as_signed(self.imm << 2, 18)
		false_addr = self.addr + 4
		cmp_expr = il.compare_unsigned_greater_than(4, get_reg(self.rX, il), get_reg(self.rY, il))
		return create_if_expr(cmp_expr, true_addr, false_addr, il)

class instr_bgeu(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RI
		self.populate_operands()

	def instruction_text(self):
		res = [InstructionTextToken(InstructionTextTokenType.TextToken, '%-6s' % self.mnemonic)]
		res.extend([
			InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rX]),
			InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rY]),
			InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, '%#x' % (self.addr + utils.as_signed(self.imm << 2, 18)), self.addr + utils.as_signed(self.imm << 2, 18), size=4)
		])
		return res

	def branching_info(self):
		return [
			(BranchType.TrueBranch, self.addr + utils.as_signed(self.imm << 2, 18)),
			(BranchType.FalseBranch, self.addr + 4)
		]

	def instruction_llil(self, il):
		true_addr = self.addr + utils.as_signed(self.imm << 2, 18)
		false_addr = self.addr + 4
		cmp_expr = il.compare_unsigned_greater_equal(4, get_reg(self.rX, il), get_reg(self.rY, il))
		return create_if_expr(cmp_expr, true_addr, false_addr, il)

class instr_call(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_RR
		self.populate_operands()
		self.rX = self.rY

	# indirect call != indirect branch, so that's why we should return `None`
	# instead of `BranchType.IndirectBranch`
	def branching_info(self):
		pass

	def instruction_text(self):
		res = [InstructionTextToken(InstructionTextTokenType.TextToken, '%-6s' % self.mnemonic)]
		res.extend([
			InstructionTextToken(InstructionTextTokenType.RegisterToken, '%s' % lm32_gpr[self.rX]),
		])
		return res

	def instruction_llil(self, il):
		call_target_expr = get_reg(self.rX, il)
		# set_ra_expr = il.set_reg(4, 'ra', il.const_pointer(4, self.addr+4))
		jump_expr = il.call(call_target_expr)
		# return [set_ra_expr, jump_expr]
		return jump_expr

class instr_calli(instr):
	def __init__(self, data: int, addr: int):
		super().__init__(data, addr)
		self.format = self.fmt_I
		self.populate_operands()

	def instruction_text(self):
		res = [InstructionTextToken(InstructionTextTokenType.TextToken, '%-6s' % self.mnemonic)]
		res.extend([
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, '%#x' % (self.addr + utils.as_signed(self.imm << 2, 18)), self.addr + utils.as_signed(self.imm << 2, 18), size=4)
		])
		return res

	def branching_info(self):
		return [(BranchType.CallDestination, self.addr + utils.as_signed(self.imm << 2, 28))]

	def instruction_llil(self, il):
		call_dst_expr = il.const_pointer(4, self.addr + utils.as_signed(self.imm << 2, 28))
		# set_ra_expr = il.set_reg(4, 'ra', il.const_pointer(4, self.addr+4))
		jump_expr = il.call(call_dst_expr)
		# return [set_ra_expr, jump_expr]
		return jump_expr
