import numpy as np
import matplotlib.pyplot as plt
import torch
from sklearn.metrics import accuracy_score
from torch import nn, optim
from collections import OrderedDict
import torch.nn.functional as F
import pandas as pd
from torchsummary import summary
import data_process as dp

UPDATE_RECORDS = True

class Net_nn(nn.Module):
    def __init__(self):
        super(Net_nn, self).__init__()
        # Our network consists of 3 layers. 1 input, 1 hidden and 1 output layer
        # This applies Linear transformation to input data.
        self.fc1 = nn.Linear(42, 32)
        # This applies linear transformation to produce output data
        self.fc2 = nn.Linear(32, 16)
        self.fc3 = nn.Linear(16, 9)

    # This must be implemented
    def forward(self, x):
        # Output of the first layer
        x = self.fc1(x)
        x = torch.sigmoid(x)
        x = self.fc2(x)
        x = torch.sigmoid(x)
        x = self.fc3(x)
        return x

    def predict(self, x):
        # Apply softmax to output
        pred = F.softmax(self.forward(x), dim=1)
        # print(pred.tolist())
        ans = []
        for t in pred:
            t = t.tolist()
            label = t.index(max(t))
            ans.append(label)
        return torch.tensor(ans)


class Net(nn.Module):
    def __init__(self):
        super(Net, self).__init__()
        self.feature = nn.Sequential(
            OrderedDict(
                [
                    ('conv1', nn.Conv2d(in_channels=1,
                                        out_channels=16,
                                        kernel_size=3,
                                        stride=1,
                                        padding=2
                                        )),
                    ('relu1', nn.ReLU()),
                    ('bn1', nn.BatchNorm2d(num_features=16)),  # 强行将数据标准化

                    # 32 * 5 * 5 --> 64 * 5 * 5
                    ('conv2', nn.Conv2d(in_channels=16,
                                        out_channels=32,
                                        kernel_size=3,
                                        stride=1,
                                        padding=1
                                        )),

                    ('relu2', nn.ReLU()),
                    ('bn2', nn.BatchNorm2d(num_features=32)),
                    ('pool1', nn.AvgPool2d(kernel_size=2)),

                    # 64 * 5 * 5 --> 128 * 5 * 5
                    ('conv3', nn.Conv2d(in_channels=32,
                                        out_channels=64,
                                        kernel_size=3,
                                        stride=1,
                                        padding=2
                                        )),

                    ('relu3', nn.ReLU()),
                    ('bn3', nn.BatchNorm2d(num_features=64)),
                    ('pool2', nn.AvgPool2d(kernel_size=2)),

                    # 128 * 5 * 5 --> 42 * 5 * 5
                    ('conv4', nn.Conv2d(in_channels=64,
                                        out_channels=32,
                                        kernel_size=3,
                                        stride=1,
                                        padding=2
                                        )),

                    ('relu4', nn.ReLU()),
                    ('bn4', nn.BatchNorm2d(num_features=32)),
                    ('pool3', nn.AvgPool2d(kernel_size=2)),


                ]
            )
        )

        self.classifier = nn.Sequential(

            OrderedDict(
                [
                    ('fc1', nn.Linear(in_features=32 * 2 * 2,
                                      out_features=128)),
                    # ('dropout1', nn.Dropout2d(p=0.3)),

                    ('fc2', nn.Linear(in_features=128,
                                      out_features=64)),

                    # ('dropout2', nn.Dropout2d(p=0.3)),

                    ('fc3', nn.Linear(in_features=64, out_features=2))
                ]
            )

        )

    def forward(self, x):
        print('x.shape', x.shape)
        out = self.feature(x)
        print('out.shape1', out.shape)
        out = out.view(x.size(0), -1)
        out = self.classifier(out)
        print('out.shape2', out.shape)
        return out

    def predict(self, x):
        # Apply softmax to output
        pred = F.softmax(self.forward(x), dim=1)
        # print(pred.tolist())
        ans = []
        for t in pred:
            t = t.tolist()
            label = t.index(max(t))
            ans.append(label)
        return torch.tensor(ans)


class Rnn(nn.Module):
    def __init__(self):
        super(Rnn, self).__init__()
        self.lstm = nn.LSTM(input_size=42,
                            hidden_size=64,   # rnn 隐藏单元数
                            num_layers=1,     # rnn 层数
                            batch_first=False
                            )
        self.output_layer = nn.Linear(in_features=64, out_features=2)

    def forward(self, x):
        # x shape (batch, time_step, input_size)
        # lstm_out shape (batch, time_step, output_size)
        # h_n shape (n_layers, batch, hidden_size)
        # h_c shape (n_layers, batch, hidden_size)
        lstm_out, (h_n, h_c) = self.lstm(x, None)
        output = self.output_layer(lstm_out[:, -1, :])  # 选择最后时刻lstm的输出
        # print(output.shape)
        return output

    def predict(self, x):
        # Apply softmax to output
        pred = F.softmax(self.forward(x), dim=1)
        # print(pred.tolist())
        ans = []
        for t in pred:
            t = t.tolist()
            label = t.index(max(t))
            ans.append(label)
        return torch.tensor(ans)


def detect_cnn(connection):
    cnn = torch.load('recognizer/model_cnn_9.pkl')
    connection = dp.data_trans_cnn(connection)
    ans = cnn.predict(connection)
    return ans[0]


def detect_nn(connection):
    nn = torch.load('recognizer/model4.pkl')
    connection = dp.data_trans_nn(connection)
    ans = nn.predict(connection)
    return ans[0]


def detect_rnn(connection):
    rnn = torch.load('recognizer/model_lstm_1.pkl')
    connection = dp.data_trans_rnn(connection)
    ans = rnn.predict(connection)
    return ans[0]

'''
# cnn = torch.load('recognizer/model_cnn_9.pkl')
nn = torch.load('recognizer/model4.pkl')
# rnn = torch.load('recognizer/model_lstm_1.pkl')
if UPDATE_RECORDS:
    dp.data_processing("logs/log_con.csv")
# x_cnn = dp.read_data("logs/records.csv", 'cnn')  # "../nn/testing_nom.csv"
x_nn = dp.read_data("logs/records.csv", 'nn')
# x_rnn = dp.read_data("logs/records.csv", 'rnn')

# ans1 = net1.predict(x_test)

# ans1 = cnn.predict(x_cnn)
ans2 = nn.predict(x_nn)
# ans3 = rnn.predict(x_rnn)

print(ans2)
'''

