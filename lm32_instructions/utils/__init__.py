from . import token

def as_signed(val, bits):
	sign_mask   = 1 << (bits -1)
	value_mask  = sign_mask - 1
	return (val & value_mask) - (val & sign_mask)
