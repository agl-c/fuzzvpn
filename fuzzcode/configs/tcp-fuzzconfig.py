#! /usr/bin/env python3
large_value = 2**70

# this python program reads a normal config file and generates various fuzzed malformed config files 
# after that, the directory including the fuzzed configs will be tested by the script tcp-testconfig.sh
# after that, test logs will be generated and analyse-log.sh will analyse them and generate report 


def modify_variable_in_file(input_file, output_file, variable_name, fuzz_way):
    with open(input_file, 'r') as infile:
        lines = infile.readlines()

    with open(output_file, 'w') as outfile:
        for line in lines:
            
            parts = line.split()

            if len(parts) == 0 or parts[0][0]=='#':
                continue
            # since it has 3 parts, we handle it here, changing the 2 following values together
            if (parts[0]=='keepalive' and parts[0]==variable_name) or (parts[0]=='server' and parts[0]==variable_name) or (parts[0]=='remote' and parts[0]==variable_name):
                if fuzz_way=='zero':
                    print(parts)
                    parts[1] = str(0)
                    parts[2] = str(0)

                elif fuzz_way == 'large':
                    parts[1] = str(large_value)
                    parts[2] = str(large_value)

                elif fuzz_way == 'add_null':
                    parts[1] = parts[1][0] + '\0' + parts[1][2:]
                    parts[2] = parts[2][0] + '\0' + parts[2][2:]
            
            elif parts[0] == variable_name:
                if fuzz_way=='zero':
                    parts[1] = str(0)
                elif fuzz_way == 'large':
                    parts[1] = str(large_value)
                elif fuzz_way == 'add_null': # for now, we change the second character of the value str to be NULL 
                    parts[1] = parts[1][0] + '\0' + parts[1][2:]
                elif fuzz_way == "malport":
                    parts[1] = str(70000) # for now, we use 70000 as the mal port
                
            if len(parts) == 1:
                outfile.write(f"{parts[0]}\n")
            elif len(parts) == 2:
                outfile.write(f"{parts[0]} {parts[1]}\n")
            elif len(parts) == 3:
                outfile.write(f"{parts[0]} {parts[1]} {parts[2]}\n")

input_file = 'tcp-server-raw-fuzz.conf'
output_dir = '/tcp-fuzzedconfigs/'

# numeric values
for variable_name in ['port', 'keepalive', 'server']:
    for fuzz_way in ['zero', 'large']:
        output_file = output_dir + 'tcp-server-raw-' + variable_name + '-' + fuzz_way + '.conf'
        modify_variable_in_file(input_file, output_file, variable_name, fuzz_way)


# all the options, we try the NULL way with all of them 
for variable_name in ['port', 'keepalive', 'server',
 'proto', 'dev', 'allow-compression', 'ca', 'cert', 'key', 'dh', 
 'data-ciphers-fallback', 'topology', 'user', 'group']:
    output_file = output_dir + 'tcp-server-raw-' + variable_name + '-add_null.conf'
    modify_variable_in_file(input_file, output_file, variable_name, 'add_null')


variable_name = "port"
output_file = output_dir + 'tcp-server-raw-' + variable_name + '-malport.conf'
modify_variable_in_file(input_file, output_file, variable_name, 'malport')
# 6+14+1=21 

# below, we generate fuzzed client configs 
input_file = 'tcp-client1-raw-fuzz.ovpn'

# numeric values
for variable_name in ['lport', 'remote']:
    for fuzz_way in ['zero', 'large']:
        output_file = output_dir + 'tcp-client1-raw-' + variable_name + '-' + fuzz_way + '.ovpn'
        modify_variable_in_file(input_file, output_file, variable_name, fuzz_way)


# all the options, we try the NULL way with all of them 
for variable_name in ['lport', 'remote',
 'proto', 'dev', 'allow-compression', 'data-ciphers-fallback', 'remote-cert-tls']:
    output_file = output_dir + 'tcp-client1-raw-' + variable_name + '-add_null.ovpn'
    modify_variable_in_file(input_file, output_file, variable_name, 'add_null')
 
variable_name = "lport"
output_file = output_dir + 'tcp-client1-raw-' + variable_name + '-malport.ovpn'
modify_variable_in_file(input_file, output_file, variable_name, 'malport')

# 4+7+1=12


def append_variable_in_file(input_file, output_file, variable_name, fuzz_way):
    with open(input_file, 'r') as infile:
        lines = infile.readlines()

    with open(output_file, 'w') as outfile:
        for line in lines:
            parts = line.split()
            if len(parts) == 0 or parts[0][0]=='#':
                continue
            if len(parts) == 1:
                outfile.write(f"{parts[0]}\n")
            elif len(parts) == 2:
                outfile.write(f"{parts[0]} {parts[1]}\n")
            elif len(parts) == 3:
                outfile.write(f"{parts[0]} {parts[1]} {parts[2]}\n")

        # now append the new variable and value
        if fuzz_way=="zero":
            outfile.write(f"{variable_name} 0\n")

        elif fuzz_way=="large":
            outfile.write(f"{variable_name} {str(large_value)}\n")


input_file = 'tcp-server-raw-fuzz.conf'
output_dir = '/tcp-fuzzedconfigs/'

# numeric values
for variable_name in ['nice', 'script-security', 'status-version', 'mute', 'verb', 'tran-window', 'key-direction',
'max-clients', 'max-routes-per-client', 'vlan-pvid', 'reneg-bytes', 'reneg-pkts', 'reneg-sec', 
'hand-window', 'tls-timeout', 'ping', 'ping-exit', 'ping-restart', 'replay-window',
'max-packet-size', 'route-delay', 'tun-mtu-extra', 'management-log-cache', 'tap-sleep', 'bcast-buffers']:
    for fuzz_way in ['zero', 'large']:
        output_file = output_dir + 'tcp-server-raw-' + variable_name + '-' + fuzz_way + '.conf'
        append_variable_in_file(input_file, output_file, variable_name, fuzz_way)

# 50

# below, we generate fuzzed client configs 
input_file = 'tcp-client1-raw-fuzz.ovpn'

# numeric values
for variable_name in ['nice', 'script-security', 'status-version', 'mute', 'verb', 'tran-window', 'key-direction'
'connect-retry', 'connect-retry-max', 'connect-timeout', 'explicit-exit-notify', 'inactive', 'resolve-retry', 'server-poll-timeout',
'reneg-bytes', 'reneg-pkts', 'reneg-sec', 
'hand-window', 'tls-timeout', 'ping', 'ping-exit', 'ping-restart', 'replay-window',
'session-timeout', 'max-packet-size',  'route-delay', 'tun-mtu-extra', 'management-log-cache', 'tap-sleep', 'bcast-buffers']:
    for fuzz_way in ['zero', 'large']:
        output_file = output_dir + 'tcp-client1-raw-' + variable_name + '-' + fuzz_way + '.ovpn'
        append_variable_in_file(input_file, output_file, variable_name, fuzz_way)

# 60 
# 110 + 33 = 143
