import struct
# https://burtleburtle.net/bob/hash/evahash.html

def sub(a, b):
    return (a - b) & 0xffffffff
  
def xor(a, b):
    return (a ^ b) & 0xffffffff
    
def mix(a, b, c):
  a = sub(a, b); a = sub(a, c); a=xor(a, c >> 13)
  b = sub(b, c); b = sub(b, a); b=xor(b, a << 8)
  c = sub(c, a); c = sub(c, b); c=xor(c, b >> 13)

  a = sub(a, b); a = sub(a, c); a=xor(a, c >> 12)
  b = sub(b, c); b = sub(b, a); b=xor(b, a << 16)
  c = sub(c, a); c = sub(c, b); c=xor(c, b >> 5)

  a = sub(a, b); a = sub(a, c); a=xor(a, c >> 3)
  b = sub(b, c); b = sub(b, a); b=xor(b, a << 10)
  c = sub(c, a); c = sub(c, b); c=xor(c, b >> 15)
  
  return a, b, c
  
def bobhash(k, initval=1):
    a = 0x9e3779b9
    b = 0x9e3779b9
    c = initval
    
    origlen = len(k)
    
    while len(k) >= 12:
        a = (a + struct.unpack("<I", k[0:4])[0]) & 0xffffffff
        b = (b + struct.unpack("<I", k[4:8])[0]) & 0xffffffff
        c = (c + struct.unpack("<I", k[8:12])[0]) & 0xffffffff
        
        a, b, c = mix(a, b, c)
        
        k = k[12:]

    c = (c + origlen) & 0xffffffff
    
    k = k.ljust(11, b"\x00")
    
    a = (a + struct.unpack("<I", k[0:4])[0]) & 0xffffffff
    b = (b + struct.unpack("<I", k[4:8])[0]) & 0xffffffff
    c = (c + struct.unpack("<I", b"\x00" + k[8:11])[0]) & 0xffffffff
    
    a, b, c = mix(a, b, c)
    
    return c
        





#s = b"bg.txt"
# print(hex(bobhash(s)))

# print(hex(bobhash(b"") & 0x3))
# print(hex(bobhash(b"hl2") & 0x3))
# print(hex(bobhash(b"materials") & 0x3))
# print(hex(bobhash(b"console") & 0x3))
# print(hex(bobhash(b"startup_loading.vtf") & 0x3))

# coll = [[] for x in range(8)]
# data = bytes.fromhex("0076616c766500636c5f646c6c730047616d6555492e646c6c007061727469636c656d616e2e646c6c006133646170692e646c6c00436f72652e646c6c006462672e646c6c0044656d6f506c617965722e646c6c0046696c6553797374656d5f537465616d2e646c6c00686c2e65786500686c64732e65786500484c54562d526561646d652e74787400686c74762e63666700686c74762e6578650068772e646c6c006b7665722e6b70006c616e67756167652e696e66004d70336465632e617369004d737333322e646c6c004d73737631322e617369004d73737632392e61736900726561646d652e7478740073772e646c6c00766775692e646c6c0076677569322e646c6c00766f6963655f6d696c65732e646c6c00766f6963655f73706565782e646c6c")
# parts = data.split(b"\x00")

# parts = (
# b'',
# b'valve',
# b'cl_dlls',
# b'gameui.dll',
# b'particleman.dll',
# b'a3dapi.dll',
# b'core.dll',
# b'dbg.dll',
# b'demoplayer.dll',
# b'filesystem_steam.dll',
# b'hl.exe',
# b'hlds.exe',
# b'hltv-readme.txt',
# b'hltv.cfg',
# b'hltv.exe',
# b'hw.dll',
# b'kver.kp',
# b'language.inf',
# b'mp3dec.asi',
# b'mss32.dll',
# b'mssv12.asi',
# b'mssv29.asi',
# b'readme.txt',
# b'sw.dll',
# b'vgui.dll',
# b'vgui2.dll',
# b'voice_miles.dll',
# b'voice_speex.dll',
# )

# for i in range(len(parts)):
    # print(i, repr(parts[i]))
    # coll[bobhash(parts[i]) & 7].append(i)
    
# for i in range(8):
    # print(i, coll[i])
    
    




