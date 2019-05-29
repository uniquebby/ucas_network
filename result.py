import matplotlib.pyplot as plt
import numpy as np


def readfile(filename):
	data_list = []
	data_num = 0
	with open(filename, 'r') as f:
		for line in f.readlines():
			linestr = line.strip('\n')
			data_list.append(float(linestr))
			data_num += 1

	return data_list, data_num

rtt_time = 0.01
y_list,num = readfile("./cwnd.dat")
x_list = [rtt_time * i for i in range(num)]

plt.plot(x_list, y_list)
plt.show()

