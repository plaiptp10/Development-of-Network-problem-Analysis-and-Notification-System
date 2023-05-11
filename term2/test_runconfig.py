import configparser
import json

#Read config.ini file
config_obj = configparser.ConfigParser()
config_obj.read("./configfile.ini")
usersetting = config_obj["usersetting"]
# set your parameters for the database connection URI using the keys from the configfile.ini
run_type = usersetting["runtype"]
pcap_file = usersetting["pcapfile"]
nw_interface = usersetting["networkinterface"]
parse_type = usersetting["parsetype"]
receiver = usersetting["receiver"]
option_values = config_obj.get("usersetting", "receiver")
option_value_list = json.loads(option_values)

# print('User variable = ', run_type, '\n')
# print('Password variable = ', pcap_file, '\n')
# print('Host variable = ', nw_interface, '\n')
# print('Port variable = ', parse_type, '\n')
# print('Database variable = ', list(str(receiver)), '\n')
print(option_value_list[1])
print(receiver[0])