import torch
import torch.nn as nn
from torch import Tensor
from typing import Any, Callable, List, Optional, Type, Union
from torch.utils.cpp_extension import load

class BasicBlock(nn.Module):
  def __init__(self, c, k):
    super().__init__()
    self.fc1 = nn.Linear(c, k, bias=False)
    self.bn1 = nn.BatchNorm1d(k)
    self.fc2 = nn.Linear(k, k, bias=False)
    self.bn2 = nn.BatchNorm1d(k)
    self.relu = nn.ReLU(inplace=True)
    self.downsample = None
    if c != k:
      self.downsample = nn.Sequential(
        nn.Linear(c, k, bias=False),
        nn.BatchNorm1d(k)
      )
  def forward(self, x):
    identity = x
    x = self.fc1(x)
    x = self.bn1(x)
    x = self.relu(x)
    x = self.fc2(x)
    x = self.bn2(x)
    if self.downsample is not None:
      identity = self.downsample(identity)
    x += identity
    x = self.relu(x)
    
    return x

class MyModel(nn.Module):
  def __init__(self, W):
    super().__init__()
    self.conv1 = BasicBlock(11, 64)
    self.conv2 = nn.Sequential(
      BasicBlock(64, 64),
      BasicBlock(64, 64)
    )
    self.conv3 = nn.Sequential(
      BasicBlock(64, 128),
      BasicBlock(128, 128)
    )
    self.conv4 = nn.Sequential(
      BasicBlock(128, 256),
      BasicBlock(256, 256)
    )
    self.conv5 = nn.Sequential(
      BasicBlock(256, 512),
      BasicBlock(512, 512)
    )
    self.fc = nn.Linear(512, 2)

    for m in self.modules():
      if isinstance(m, nn.Linear):
        nn.init.kaiming_normal_(m.weight, mode='fan_out', nonlinearity='relu')
      elif isinstance(m, nn.BatchNorm1d):
        nn.init.constant_(m.weight, 1)
        nn.init.constant_(m.bias, 0)

  def forward(self, x):
    x = self.conv1(x)
    x = self.conv2(x)
    x = self.conv3(x)
    x = self.conv4(x)
    x = self.conv5(x)
    x = self.fc(x)
    return x

if __name__ == "__main__":
  helper = load(
    name = 'helper',
    sources = ['helper.cpp', 'DES.cpp'],
    with_cuda=False,
    extra_cflags=['-O3']
  )
  print('helper loaded!')

  # constants
  nepoch = 100000
  train_dataset_sz = 100000
  test_dataset_sz = 10000
  max_bsz = 1000

  # generate dataset
  X_train = torch.empty([train_dataset_sz, 11], dtype=torch.float32)
  Y_train = torch.empty([train_dataset_sz], dtype=torch.long)
  X_test = torch.empty([test_dataset_sz, 11], dtype=torch.float32)
  Y_test = torch.empty([test_dataset_sz], dtype=torch.long)
  helper.set_seed(42)
  helper.gen_dataset(train_dataset_sz, X_train, Y_train)
  helper.gen_dataset(test_dataset_sz, X_test, Y_test)

  # model train
  model = MyModel(11).cuda()
  criterion = nn.CrossEntropyLoss()
  optimizer = torch.optim.Adam(model.parameters(), lr=1e-6)
  for epoch in range(nepoch):
    print('epoch:', epoch)
    print('training...')
    model.train()
    for data_idx in range(0, train_dataset_sz, max_bsz):
      if train_dataset_sz - data_idx < max_bsz:
        continue
      x = X_train[data_idx:data_idx+max_bsz].cuda()
      y = Y_train[data_idx:data_idx+max_bsz].cuda()
      optimizer.zero_grad()
      output = model(x)
      loss = criterion(output, y)
      loss.backward()
      optimizer.step()
    print('testing...')
    model.eval()
    correct = 0
    for data_idx in range(0, test_dataset_sz, max_bsz):
      x = X_test[data_idx:data_idx+max_bsz].cuda()
      y = Y_test[data_idx:data_idx+max_bsz].cuda()
      output = model(x)
      score = torch.argmax(output, dim=1) == y
      correct += score.sum().item()
    print(f'accuracy: {correct / test_dataset_sz}, ({correct} / {test_dataset_sz})')