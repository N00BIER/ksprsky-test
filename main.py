import csv
import struct
import math
from auxiliary import string2hex, nocarryforward, get_rbytes 

def main():
  
# ------------- dword hex values extracted during debugging of stage 1 -----------
  with open('./stack.txt', 'r') as file:
    for line in file:
      line = line.strip('\n')
      line = line.lstrip('00')
      key,val = line.split(',')
      stack_hexes[int(key,16)] = int(val,16)

# ------------- reading text to encrypt from .dat file -------------------
  with open('./input.dat', 'r') as file:
    text = file.read()
  
  # --------- stage 2 key extracted during debugging ---------------------
  with open('./s2_key.txt', 'r') as file:
    for line in file:
      s2_key = line.split(' ')  # ----> ascii Q38B7[JPX4p$A`b]Em2/V@%c)Nl6GroRque+UhCsSid5j'>;^1(O=!LK\I"F*Y9,<T.WZ_&t?fDMan:#-k0Hg
      s2_key = [int(('0x'+chr),16) for chr in s2_key]
  
  text_length = len(text)
  
  # ------- text padding --------------------------------------
  if text_length % 8 != 0:
    pad_length = (8 - text_length % 8)
    pad_chr = bytes.fromhex('0'+str(pad_length)).decode('cp1252')
    pad_text = text + pad_chr*pad_length
  else:
    pad_text = text
  
  pad_text_list = list(map(''.join, zip(*[iter(pad_text)]*4)))
  
  step = 2
  length = len(pad_text_list)
  index = 0
  
  # --------- executing stage 1 encryption -----------------------
  for index in range(0,length,2):
    s1_output = fun4033f4(pad_text_list,stack_start,index)

  #----------- processing stage 1 output for stage 2 ---------------------------
  s1_output = [int(chr,16) for chr in s1_output]

  processed = []

  for i in range(0,len(s1_output),4):
    processed.append(hex(((((((s1_output[i] << 8) | s1_output[i+1]) << 8) | s1_output[i+2]) << 8) | s1_output[i+3])))
  
  s2_dict = dict(zip(s2_addr,s2_key))
  
  #---------- executing stage 2 encryption ----------------------------------
  for hexstr in processed:
    i  = 4
    while i > -1:
      remainder = int(hex(int(hexstr,16) % 0x55),16)
      s2_output.append(s2_dict[s2_saddr + remainder])
      i-=1
      hexstr = '0x{:x}'.format(int(int(hexstr,16) / 0x55))
      
  
  raw_string = ''.join([bytes.fromhex(hex(i).lstrip('0x')).decode('utf-8') for i in s2_output])
  output = ''.join([i[::-1] for i in list(map(''.join, zip(*[iter(raw_string)]*5)))])
  
  foutput = open('output.dat', 'w')
  foutput.write(output)
  foutput.close()

# ------------------------------STAGE 1-----------------------------------------------------------
#--> @ret fun40377C
#--> fun4033F4 function performs encryption at stage 1

def fun4033f4(txt,stack_start,index):

  ecx = stack_start
  edi = string2hex(txt[index+1])
  esi = ebx = eax = string2hex(txt[index]) ^ stack_hexes[ecx]
  esi = esi >> 0x10
  eax = eax >> 0x18
  edx = esi
  esi = get_rbytes(esi,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = nocarryforward((esi + stack_hexes[ecx + eax * 0x4 + 0x48]))
  eax = get_rbytes((ebx >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + eax * 0x4 + 0x848]
  eax = get_rbytes(ebx,1)
  ebx = ebx ^ stack_hexes[ecx + 0x8]
  esi = nocarryforward((esi + stack_hexes[ecx + eax * 0x4 + 0xC48]))
  eax = stack_hexes[ecx + 0x4]
  
  eax = eax ^ edi
  eax = eax ^ esi
  esi = eax
  edi = eax
  esi = esi >> 0x10
  edi = edi >> 0x18
  edx = esi
  esi = get_rbytes(edx,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = esi + stack_hexes[ecx + edi * 0x4 + 0x48]
  edi = get_rbytes((eax >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + edi * 0x4 + 0x848]
  edi = get_rbytes(eax,1)
  eax = eax ^ stack_hexes[ecx + 0xc]
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0xC48]))
  
  ebx = ebx ^ esi
  esi = ebx
  edi = ebx
  esi = esi >> 0x10
  edi = edi >> 0x18
  edx = esi
  esi = get_rbytes(edx,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = esi + stack_hexes[ecx + edi * 0x4 + 0x48]
  edi = get_rbytes((ebx >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + edi * 0x4 + 0x848]
  edi = get_rbytes(ebx,1)
  ebx = ebx ^ stack_hexes[ecx + 0x10]
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0xC48]))
  
  eax = eax ^ esi
  esi = eax
  edi = eax
  esi = esi >> 0x10
  edi = edi >> 0x18
  edx = esi
  esi = get_rbytes(edx,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = esi + stack_hexes[ecx + edi * 0x4 + 0x48]
  edi = get_rbytes((eax >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + edi * 0x4 + 0x848]
  edi = get_rbytes(eax,1)
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0xC48]))
  ebx = ebx ^ esi
  esi = ebx
  edi = ebx
  esi = esi >> 0x10
  edi = edi >> 0x18
  edx = esi
  esi = get_rbytes(edx,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = esi + stack_hexes[ecx + edi * 0x4 + 0x48]
  edi = get_rbytes((ebx >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + edi * 0x4 + 0x848]
  edi = get_rbytes(ebx,1)
  eax = eax ^ stack_hexes[ecx + 0x14]
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0xC48]))
  ebx = ebx ^ stack_hexes[ecx + 0x18]
  eax = eax ^ esi
  esi = eax
  edi = eax
  esi = esi >> 0x10
  edi = edi >> 0x18
  edx = esi
  esi = get_rbytes(edx,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = esi + stack_hexes[ecx + edi * 0x4 + 0x48]
  edi = get_rbytes((eax >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + edi * 0x4 + 0x848]
  edi = get_rbytes(eax,1)
  eax = eax ^ stack_hexes[ecx + 0x1c]
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0xC48]))
  ebx = ebx ^ esi
  esi = ebx
  edi = ebx
  esi = esi >> 0x10
  edi = edi >> 0x18
  edx = esi
  esi = get_rbytes(edx,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = esi + stack_hexes[ecx + edi * 0x4 + 0x48]
  edi = get_rbytes((ebx >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + edi * 0x4 + 0x848]
  edi = get_rbytes(ebx,1)
  ebx = ebx ^ stack_hexes[ecx + 0x20]
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0xC48]))
  eax = eax ^ esi
  esi = eax
  edi = eax
  esi = esi >> 0x10
  edi = edi >> 0x18
  edx = esi
  esi = get_rbytes(edx,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = esi + stack_hexes[ecx + edi * 0x4 + 0x48]
  edi = get_rbytes((eax >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + edi * 0x4 + 0x848]
  edi = get_rbytes(eax,1)
  eax = eax ^ stack_hexes[ecx + 0x24]
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0xC48]))
  ebx = ebx ^ esi
  esi = ebx
  edi = ebx
  esi = esi >> 0x10
  edi = edi >> 0x18
  edx = esi
  esi = get_rbytes(edx,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = esi + stack_hexes[ecx + edi * 0x4 + 0x48]
  edi = get_rbytes((ebx >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + edi * 0x4 + 0x848]
  edi = get_rbytes(ebx,1)
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0xC48]))
  eax = eax ^ esi
  esi = eax
  edi = eax
  esi = esi >> 0x10
  edi = edi >> 0x18
  ebx = ebx ^ stack_hexes[ecx + 0x28]
  edx = esi
  esi = get_rbytes(edx,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0x48]))
  edi = get_rbytes((eax >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + edi * 0x4 + 0x848]
  edi = get_rbytes(eax,1)
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0xC48]))
  ebx = ebx ^ esi
  esi = ebx
  edi = ebx
  esi = esi >> 0x10
  edi = edi >> 0x18
  edx = esi
  esi = get_rbytes(edx,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = esi + stack_hexes[ecx + edi * 0x4 + 0x48]
  edi = get_rbytes((ebx >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + edi * 0x4 + 0x848]
  edi = get_rbytes(ebx,1)
  esi = nocarryforward(esi + stack_hexes[ecx + edi * 0x4 + 0xC48])
  eax = eax ^ stack_hexes[ecx + 0x2c]
  ebx = ebx ^ stack_hexes[ecx + 0x30]
  eax = eax ^ esi
  esi = eax
  edi = eax
  esi = esi >> 0x10
  edi = edi >> 0x18
  edx = esi
  esi = get_rbytes(edx,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0x48]))
  edi = get_rbytes((eax >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + edi * 0x4 + 0x848]
  edi = get_rbytes(eax,1)
  eax = eax ^ stack_hexes[ecx + 0x34]
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0xC48]))
  ebx = ebx ^ esi
  esi = ebx
  edi = ebx
  esi = esi >> 0x10
  edi = edi >> 0x18
  edx = esi
  esi = get_rbytes(edx,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0x48]))
  edi = get_rbytes((ebx >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + edi * 0x4 + 0x848]
  edi = get_rbytes(ebx,1)
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0xC48]))
  eax = eax ^ esi
  esi = eax
  edi = eax
  esi = esi >> 0x10
  edi = edi >> 0x18
  edx = esi
  esi = get_rbytes(edx,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0x48]))
  edi = get_rbytes((eax >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + edi * 0x4 + 0x848]
  edi = get_rbytes(eax,1)
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0xC48]))
  ebx = ebx ^ stack_hexes[ecx + 0x38]
  eax = eax ^ stack_hexes[ecx + 0x3c]
  ebx = ebx ^ esi
  esi = ebx
  edi = ebx
  esi = esi >> 0x10
  edi = edi >> 0x18
  edx = esi
  esi = get_rbytes(edx,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0x48]))
  edi = get_rbytes((ebx >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + edi * 0x4 + 0x848]
  edi = get_rbytes(ebx,1)
  ebx = ebx ^ stack_hexes[ecx + 0x40]
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0xC48]))
  eax = eax ^ esi
  esi = eax
  edi = eax
  esi = esi >> 0x10
  edi = edi >> 0x18
  edx = esi
  esi = get_rbytes(edx,1)
  
  esi = stack_hexes[ecx + esi * 0x4 + 0x448]
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0x48]))
  edi = get_rbytes((eax >> 0x8),1)
  esi = esi ^ stack_hexes[ecx + edi * 0x4 + 0x848]
  edi = get_rbytes(eax,1)
  eax = eax ^ stack_hexes[ecx + 0x44]
  esi = nocarryforward((esi + stack_hexes[ecx + edi * 0x4 + 0xC48]))
  
  ecx = eax
  
  s1_output.append(hex(get_rbytes((eax>>0x18),1)))
  s1_output.append(hex(get_rbytes((eax>>0x10),1)))
  s1_output.append(hex(get_rbytes((eax>>0x8),1)))
  s1_output.append(hex(get_rbytes(eax,1)))
  ebx = ebx ^ esi
  s1_output.append(hex(get_rbytes((ebx>>0x18),1)))
  s1_output.append(hex(get_rbytes((ebx>>0x10),1)))
  s1_output.append(hex(get_rbytes((ebx>>0x8),1)))
  s1_output.append(hex(get_rbytes(ebx,1)))
  
  return s1_output

if __name__=='__main__':
  stack_hexes = {}
  stack_start = 0x60EDD8
  stack_end = 0x60FDD8
  s2_saddr = 0x650f78
  s1_output = []
  s2_key = []
  s2_addr = [s2_saddr + i for i in range(85)]
  s2_output = []
  main()

