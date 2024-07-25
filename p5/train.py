import torch
from torch.utils.cpp_extension import load

helper = load(
  name = 'helper',
  sources = ['helper.cpp', 'DES.cpp']
)

c = helper.test(1, 2)
print(c)

helper.gen_dataset([], [])

import binascii
from Crypto.Cipher import DES as DES_ref
pt = binascii.unhexlify('369E4BAFD0F79208')
key = binascii.unhexlify('944B0481B503F64F')
print(pt, key)
ct = DES_ref.new(key, DES_ref.MODE_ECB).encrypt(pt)
print(binascii.hexlify(ct))
