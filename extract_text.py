# Extract .text section from PE stub -> raw binary
import struct, sys
with open(sys.argv[1], 'rb') as f:
    d = f.read()
e_lfanew = struct.unpack('<I', d[0x3C:0x40])[0]
num_sec = struct.unpack('<H', d[e_lfanew+6:e_lfanew+8])[0]
opt_sz = struct.unpack('<H', d[e_lfanew+20:e_lfanew+22])[0]
s = e_lfanew + 24 + opt_sz
for i in range(num_sec):
    off = s + i * 40
    name = d[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
    raw_sz = struct.unpack('<I', d[off+16:off+20])[0]
    raw_off = struct.unpack('<I', d[off+20:off+24])[0]
    vsz = struct.unpack('<I', d[off+8:off+12])[0]
    if name in ('.text', 'CODE', 'TEXT'):
        sz = raw_sz if raw_sz else vsz
        with open(sys.argv[2], 'wb') as out:
            out.write(d[raw_off:raw_off+sz])
        print(f"Extracted {sz} bytes -> {sys.argv[2]}")
        break
