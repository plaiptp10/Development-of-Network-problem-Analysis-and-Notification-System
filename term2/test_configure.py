import configparser

config = configparser.ConfigParser()

# Add the structure to the file we will create
config.add_section('usersetting')
config.set('usersetting', 'Run Type', 'Live or File')
config.set('usersetting', 'Pcap File', 'pcap/icmp.pcap')
config.set('usersetting', 'Network Interface', 'Wi-Fi 2')
config.set('usersetting', 'Parse Type', 'tcp')
config.set('usersetting', 'receiver', 'Email receiver')

# Write the new structure to the new file
with open(r"./configfiletest.ini", 'w') as configfile:
    config.write(configfile)