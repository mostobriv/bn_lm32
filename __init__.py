import binaryninja
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken, InstructionTextTokenType
from binaryninja.enums import BranchType

import collections
import struct

from .lm32_instructions import *
from .lm32_instructions.base import lm32_gpr


def trace_retval(func):
	def inner(*args, **kwargs):
		retval = func(*args, **kwargs)
		# print("%s at %#x with (%s)-> %d" % (func.__name__, args[2], args[1], retval))
		return retval
	return inner

class Lm32CallingConvenvtion(binaryninja.CallingConvention):
	# name = "Default"
	int_arg_regs = ['r%d' % i for i in range(1, 6)]
	int_return_reg = "r1"

class Lm32(Architecture):
	name = 'Lattice Mico32'

	endianness = binaryninja.enums.Endianness.BigEndian

	address_size = 4
	default_int_size = 4
	instr_alignment = 4
	max_instr_length = 4
	link_reg = 'ra'

	# general purpose registers
	regs = {i:RegisterInfo(i, 4) for i in lm32_gpr}

	# control status registers
	regs.update({
		"pc": RegisterInfo("pc", 4), # not indexed
	})

	regs.update({
		"IE": RegisterInfo("IE", 4), # 0
	})

	global_regs = ["r0"]

	stack_pointer = 'sp'

	def get_instruction_info(self, data, addr):
		if len(data) < 4:
			return None

		info = InstructionInfo()
		info.length = 4

		data = data[:4]
		ins = lm32_instructions.decode_instruction(data, addr)
		branching_info = ins.branching_info()
		if branching_info is not None:
			for bi in branching_info:
				info.add_branch(*bi)

		return info

	def get_instruction_text(self, data, addr):
		if len(data) < 4:
			return (), 0

		data = data[:4]
		return lm32_instructions.decode_instruction(data, addr).instruction_text(), 4

	@trace_retval # 4002d9a8
	def get_instruction_low_level_il(self, data, addr, il):
		if len(data) < 4:
			return None

		# print("%#x" % addr)
		data = data[:4]
		ins = lm32_instructions.decode_instruction(data, addr)
		obj = ins.instruction_llil(il)
		if type(obj) is list:
			for il_ins in obj:
				il.append(il_ins)
		elif obj is None:
			pass
		else:
			il.append(obj)

		return 4


Lm32.register()

_lm32_arch = Architecture['Lattice Mico32']

_lm32_arch.register_calling_convention(Lm32CallingConvenvtion(_lm32_arch, "simple_cc"))
# Lm32.default_calling_convention = Lm32CallingConvenvtion(_lm32_arch, 'default')

binaryninja.binaryview.BinaryViewType['ELF'].register_arch(
	138, binaryninja.enums.Endianness.BigEndian, _lm32_arch
)