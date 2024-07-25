import torch
from torch.utils.cpp_extension import load

helper = load(
  name = 'helper',
  sources = ['helper.cpp', 'DES.cpp'],
  with_cuda=False,
  extra_cflags=['-O3']
)

#helper.gen_dataset([], [])
helper.test_k_iteration()

