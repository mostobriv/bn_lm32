import struct

from . import ariphmetic_instructions
from . import logic_instructions
from . import shift_instructions
from . import comparison_instructions
from . import flow_control_instructions
from . import data_transfer_instructions
from . import pseudo_instructions

def decode_instruction(data, addr):
	op2ins = {
		0: shift_instructions.instr_srui,
		# 1: instr_nori,
		2: ariphmetic_instructions.instr_muli,
		# 3: instr_sh,
		# 4: instr_lb,
		# 5: instr_sri,
		6: logic_instructions.instr_xori,
		# 7: instr_lh,
		8: logic_instructions.instr_andi,
		# 9: instr_xnori,
		10: data_transfer_instructions.instr_lw,
		11: data_transfer_instructions.instr_lhu,
		12: data_transfer_instructions.instr_sb,
		13: ariphmetic_instructions.instr_addi,
		14: logic_instructions.instr_ori,
		15: shift_instructions.instr_sli,
		16: data_transfer_instructions.instr_lbu,
		17: flow_control_instructions.instr_be,
		# 18: instr_bg,
		# 19: instr_bge,
		20: flow_control_instructions.instr_bgeu,
		21: flow_control_instructions.instr_bgu,
		22: data_transfer_instructions.instr_sw,
		23: flow_control_instructions.instr_bne,
		# 24: instr_andhi,
		# 25: instr_cmpei,
		# 26: instr_cmpgi,
		# 27: instr_cmpgei,
		# 28: instr_cmpgeui,
		# 29: instr_cmpgui,
		30: logic_instructions.instr_orhi,
		# 31: instr_cmpnei,
		# 32: instr_sru,
		# 33: instr_nor,
		34: ariphmetic_instructions.instr_mul,
		# 35: instr_divu,
		# 36: instr_rcsr,
		# 37: instr_sr,
		38: logic_instructions.instr_xor,
		# 39: instr_div,
		40: logic_instructions.instr_and,
		# 41: instr_xnor,
		# 42: instr_reserved,
		# 43: instr_raise,
		# 44: instr_sextb,
		45: ariphmetic_instructions.instr_add,
		46: logic_instructions.instr_or,
		47: shift_instructions.instr_sl,
		48: flow_control_instructions.instr_b,
		# 49: instr_modu,
		50: ariphmetic_instructions.instr_sub,
		# 51: instr_reserved,
		# 52: instr_wcsr,
		# 53: instr_mod,
		54: flow_control_instructions.instr_call,
		# 55: instr_sexth,
		56: flow_control_instructions.instr_bi,
		# 57: instr_cmpe,
		# 58: instr_cmpg,
		# 59: instr_cmpge,
		# 60: instr_cmpgeu,
		# 61: instr_cmpgu,
		62: flow_control_instructions.instr_calli,
		# 63: instr_cmpne,
	}

	raw = struct.unpack('>I', data)[0]
	opcode = raw >> 26 & 0x3F
	try:
		instruction = op2ins[opcode](raw, addr)
		final_instruction = instruction.alias or instruction
	except KeyError:
		final_instruction = pseudo_instructions.instr_TODO(raw, addr)

	return final_instruction