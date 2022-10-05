
__regs = ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24', 'r25', 'gp', 'fp', 'sp', 'ra', 'ea', 'ba')

def get_reg(idx, il):
	if idx == 0:
		return il.const(4, 0)
	else:
		return il.reg(4, __regs[idx])