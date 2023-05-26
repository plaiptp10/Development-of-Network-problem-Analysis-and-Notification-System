import numpy as np
from matplotlib import pyplot as plt

# Set the figures size
plt.rcParams["figure.figsize"] = [7.50, 3.50]
plt.rcParams["figure.autolayout"] = True

# x and y data points
x = np.array([65, 90, 150, 202, 250, 279, 311, 366, 442, 607])
y = np.array([5, 13, 55, 125, 234, 322, 445, 738, 1250, 2278])

# Plot the data points
plt.title("Processing Time")
plt.xlabel("number of packets")
plt.ylabel("time(s)")
plt.grid(False)
plt.plot(x, y , marker = 'o')
plt.savefig("processtime.jpg")


# Display the plot
plt.show()

# from matplotlib import pyplot as plt
# fig = plt.figure()
# ax = fig.add_subplot()
# plt.show()
# plt.show(block=False)
# plt.close()
