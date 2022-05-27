# --------- auxiliary functions -----------

def string2hex(s):
    slist = list(s)
    hex_str = '0x'+''.join([chr.encode('cp1252').hex() for chr in slist])
    return int(hex_str,16)
  
def nocarryforward(val):
    if len(hex(val).lstrip('0x')) > 8:
      return int('0x'+hex(val)[-8:],16)
    else:
      return val

def get_rbytes(val,n):
    if len(hex(val).lstrip('0x')) == 1:
      return int(hex(val),16)
    else:
      return int('0x'+hex(val)[-2*n:],16)
