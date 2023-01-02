#!/usr/bin/env python3
import r2pipe
import sys

r = r2pipe.open(sys.argv[1])

print("Analyzing...")
r.cmd('aa;aac;aar;aav;aaef')

# Find create threads by 'Unable to start generator'
string = r.cmd('iz~Unable to start generator').split()[2]
xrefs = r.cmdj(f'axtj @ {string}')
assert len(xrefs) == 1
func_offset = xrefs[0]['fcn_addr']
print(f'create offset: {hex(func_offset)}')

# Find shutdown by 'Shutting down'
string = r.cmd('iz~Shutting down').split()[2]
xrefs = r.cmdj(f'axtj @ {string}')
assert len(xrefs) == 1
func_offset = xrefs[0]['fcn_addr']
print(f'shutdown offset: {hex(func_offset)}')

# Find wait & udpate by xrefs to usleep
xrefs = r.cmdj('axtj @ sym.imp.usleep')
assert len(xrefs) == 2
for xref in xrefs:
    func_offset = xref['fcn_addr']
    func_size = len(r.cmdj(f'afbj {func_offset}'))
    if func_size < 4:
        print(f'wait offset: {hex(func_offset)}')
    else:
        print(f'actual update offset: {hex(func_offset)}')
        xrefs = r.cmdj(f'axtj @ {func_offset}')
        if 'fcn_addr' in xrefs[0]:
            func_offset = xrefs[0]['fcn_addr']
            print(f'update offset: {hex(func_offset)}')



