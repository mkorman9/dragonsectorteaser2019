import json


def read_packets():
    packets = []

    f = open('traffic.json')
    root = json.load(f)
    f.close()

    for entry in root:
        capdata = entry['_source']['layers']['usb.capdata']
        capdata = capdata.replace(':', '').decode('hex')

        packets.append(capdata)

    return packets


def parse_inputs(packets):
    """reference: https://patchwork.kernel.org/patch/10761581/"""

    inputs = []

    for packet in packets:
        new_input = ''

        if packet[3] != '\0':
            byte3 = ord(packet[3])
            # y = byte3 & 0x01
            x = byte3 & 0x02
            # b = byte3 & 0x04
            a = byte3 & 0x08
            if x > 0:
                new_input = 'reset'
            elif a > 0:
                new_input = 'select'
        if packet[5] != '\0':
            byte5 = ord(packet[5])
            down = byte5 & 0x01
            up = byte5 & 0x02
            right = byte5 & 0x04
            left = byte5 & 0x08
            if down > 0:
                new_input = 'down'
            elif up > 0:
                new_input = 'up'
            elif right > 0:
                new_input = 'right'
            elif left > 0:
                new_input = 'left'

        inputs.append(new_input)

    return inputs


def remove_duplicate_inputs(inputs):
    filtered_inputs = []
    last_input = None

    for _input in inputs:
        if (last_input is not None) and (_input == last_input):
            continue

        if _input != '':
            filtered_inputs.append(_input)
        last_input = _input

    return filtered_inputs


packets = read_packets()
inputs = parse_inputs(packets)
inputs = remove_duplicate_inputs(inputs)

print '// add the following to app.html'
print 'var inputs = ['
for i, _input in enumerate(inputs):
    print '\t"' + _input + '"' + ('' if i == len(inputs) - 1 else ',')
print '];'
