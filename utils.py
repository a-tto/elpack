import struct

def unpack_until_null(buf, offset):
    unpacked = ''
    slide = 0
    unpacked += chr(struct.unpack_from('B', buf, offset + slide)[0])
    while unpacked[-1] != '\0':
        unpacked += chr(struct.unpack_from('B', buf, offset + slide)[0])
        slide += 1
    
    return unpacked

