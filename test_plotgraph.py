import numpy as np
from matplotlib import pyplot as plt

# Set the figures size
plt.rcParams["figure.figsize"] = [7.50, 3.50]
plt.rcParams["figure.autolayout"] = True

# x and y data points
x = [0.0222111, 0.0233111, 0.03011220]
y = [200, 210, 205]

# Plot the data points
plt.grid(False)
plt.plot(x, y)


# LaTex representation
plt.title("test plot")

# Display the plot
plt.show()

# from matplotlib import pyplot as plt
# fig = plt.figure()
# ax = fig.add_subplot()
# plt.show()
# plt.show(block=False)
# plt.close()
