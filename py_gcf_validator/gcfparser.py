import hashlib, io, os, struct, sys, time, zlib

from manifest import *

# manifest flags
# 0x00000001 UserConfigFile
# 0x00000002 LaunchFile
# 0x00000008 Locked
# 0x00000020 NocacheFile
# 0x00000040 VersionedUcFile
# 0x00000080 PurgeFile
# 0x00000100 EncryptedFile
# 0x00000200 ReadOnlyFile
# 0x00000400 HiddenFile
# 0x00000800 ExecutableFile
# 0x00004000 File

                                
class GCF:
    def __init__(self, filename):
        self.f = open(filename, "rb")
        
        # CacheDescriptor - CacheFileFixedDescBlock.cpp
        
        binheader = self.f.read(11 * 4)
        # header checksum is the sum of all header bytes apart from Checksum
        calc_csum = sum(binheader[:-4])
        
        (
            self.DescVer,
            self.CacheType,
            self.CacheVersion,
            self.AppId,
            self.AppVersionId,
            self.CacheState,
            self.CacheWriteFlag,
            self.CacheFileSize,
            self.DataBlockSize,
            self.MaxEntries,
            Checksum
        ) = struct.unpack("<11I", binheader)
        
        if self.DescVer != 1:
            raise Exception("unknown DescVer", self.DescVer)

        # 1     GCF
        # 2     NCF
        if self.CacheType not in (1, 2):
            raise Exception("unknown CacheType", self.CacheType)
            
        # for steam 2003-06, default self.CacheVersion is 3 - must be 1,2 or 3
        if self.CacheVersion not in (1, 3, 5, 6):
            raise Exception("gotta examine more!!!", self.CacheVersion)
            
        # 0     clean unmount
        # 1     dirty unmount
        if self.CacheState not in (0, 1):
            raise Exception("bad CacheState", self.CacheState)
        
        if self.CacheState == 1:
            print("warning: dirty cache")

        if self.CacheWriteFlag not in (0, 1):
            raise Exception("bad CacheWriteFlag", self.CacheWriteFlag)
            
        if self.CacheWriteFlag != 0:
            raise Exception("Unexpected CacheWriteFlag", self.CacheWriteFlag)
            
        if os.path.getsize(filename) != self.CacheFileSize:
            raise Exception("bad .GCF file size, claims to be", hex(self.CacheFileSize), "but should be", hex(os.path.getsize(filename)))
            
        if self.DataBlockSize != 0x2000:
            raise Exception("nonstandard block size", hex(self.DataBlockSize))
        
        if Checksum != calc_csum:
            raise Exception("bad header checksum", Checksum, calc_csum)
            
        print("GCF version", self.CacheVersion)
        print("AppId", self.AppId)
        print("AppVersionId", self.AppVersionId)
        print("MaxEntries", self.MaxEntries)

        (MaxEntries, EntriesInUse, NextFreeEntry, dunno1, dunno2, dunno3, dunno4) = self._read_header_with_csum32(7)

        if self.MaxEntries != MaxEntries:
            raise Exception()

        if NextFreeEntry > self.MaxEntries:
            raise Exception("NextFreeEntry", NextFreeEntry, self.MaxEntries)
        else:
            print("NextFreeEntry", NextFreeEntry)
    
        if (dunno1, dunno2, dunno3, dunno4) != (0, 0, 0, 0):
            raise Exception("non empty dunno", (dunno1, dunno2, dunno3, dunno4))
            
        print("start of entries", hex(self.f.tell()))
        self.entries = {}
        blank = None
        used = None
        for i in range(self.MaxEntries):
            flags_low, dummy0, offset, filesize, firstblock, nextblock, prevblock, manifest_idx = struct.unpack(
                "<2H6I", self.f.read(28)
            )
            flags = (dummy0 << 16) | flags_low
            entry = (flags, offset, filesize, firstblock, nextblock, prevblock, manifest_idx)
            
            if flags & 0x8000 == 0:
                # not used
                
                # if blank != None and blank != entry:
                    # print("prev blank", blank)
                    # print("curr blank", entry)
                    # raise Exception("weird blank!")
                    
                blank = entry
            else:
                # if used != None and used != (flags & 0xffff3ff8):
                    # raise Exception("weird flags!", hex(flags), hex(used), hex(i))
                    
                used = flags & 0xffff3ff8
                #print("flags", hex(flags))
                
                self.entries[i] = entry
                
        print("number of entries", len(self.entries))
        
                
        print("frag map start", hex(self.f.tell()))

        numblocks2, first_unused, tflag = self._read_header_with_csum32(3)

        print("first unused", first_unused)
        if self.MaxEntries != numblocks2:
            raise Exception()

        if tflag == 0:
            self.terminator = 0xffff
        elif tflag == 1:
            self.terminator = 0xffffffff
        else:
            raise Exception()
            
        self.fragmap = []
        for i in range(self.MaxEntries):
            self.fragmap.append(struct.unpack("<I", self.f.read(4))[0])
            
        print("block map start", hex(self.f.tell()))

        numblocks2, firstentry, lastentry, dunno = self._read_header_with_csum32(4)

        self.usagemap = []
        for i in range(self.MaxEntries):
            self.usagemap.append(struct.unpack("<II", self.f.read(8)))
            
        print("manifest start", hex(self.f.tell()))
        
        # read manifest from file stream
        self.manif = Manifest(self.f, adjust_size=True)
        
        if self.manif.adjusted:
            print("DID ADJUSTMENT")
            
        if self.CacheVersion >= 5:
            header = self.f.read(8)
            print("weird header", header.hex())
            
        print("dunno table start", hex(self.f.tell()))
        print("HACKISH REMOVE ME DUNNO WHAT THIS IS YET")

        self.f.read(self.manif.itemcount * 4)
        
        # checksums are not present in version 1
        if self.CacheVersion >= 3:
            csumstart = self.f.tell()
            print("checksums start", hex(self.f.tell()))
            
            csumversion, csumsize = struct.unpack("<2I", self.f.read(2 * 4))
            if csumversion not in (0, 1):
                raise Exception("unknown checksum version!")
                
            if csumversion == 0 and self.CacheVersion != 3:
                raise Exception("weird csumversion!")
                
            csumstart = self.f.tell()
                
            magic, dummy2, filecount, csumcount = struct.unpack("<4I", self.f.read(4 * 4))
            
            if magic != 0x14893721:
                raise Exception()
                
            if dummy2 != 1:
                raise Exception()
                
            self.checksummap = []
            for i in range(filecount):
                self.checksummap.append(struct.unpack("<2I", self.f.read(2 * 4)))
                
            self.checksums = []
            for i in range(csumcount):
                self.checksums.append(struct.unpack("<I", self.f.read(4))[0])

            csumend = self.f.tell()
            csumsignature = self.f.read(0x80)
            latest_ver = struct.unpack("<I", self.f.read(4))[0]
            print("csum size", hex(csumend - csumstart), "csum signature", csumsignature.hex())

            self.gotchecksums = True

            expected = {csumend + 0x80, csumend + 0x80 + 4}
            if csumstart + csumsize not in expected:
                raise Exception()
        else:
            self.gotchecksums = False
        
        print("blocks header start", hex(self.f.tell()))
        
        if self.CacheVersion in (5, 6):
            AppVersionId2 = struct.unpack("<I", self.f.read(4))[0]
            
            if self.AppVersionId != AppVersionId2:
                raise Exception("different appvers", self.AppVersionId, AppVersionId2)
            
        numblocks2, DataBlockSize2, self.blockoffset, blocksused = self._read_header_with_csum32(4)
        if self.MaxEntries != numblocks2:
            raise Exception()

        if self.DataBlockSize != DataBlockSize2:
            raise Exception()
            
        if self.blockoffset != self.f.tell():
            print("WARNING: differing for start of data", hex(self.blockoffset), hex(self.f.tell()), hex(self.blockoffset - self.f.tell()))

        slack = self.CacheFileSize - (self.blockoffset + self.DataBlockSize * self.MaxEntries)
        if slack > self.DataBlockSize or slack < 0:
            print("bad slack", slack)

        print("OK")

    def _read_header_with_csum32(self, n):
        res = []
        for i in range(n + 1):
            val = struct.unpack("<I", self.f.read(4))[0]
            res.append(val)
            
        calc_csum = sum(res[:-1]) & 0xffffffff
        if calc_csum != res[-1]:
            raise Exception("Bad checksum")
            
        return res[:-1]
        
    def read_data(self, firstblock, size):
        remaining = size
        data = []
        currblock = firstblock
        while currblock != self.terminator:
            #print("reading block at offset", hex(self.blockoffset + 0x2000 * currblock), "blockidx", currblock, "size", hex(size), "remaining", hex(remaining))
            
            self.f.seek(self.blockoffset + 0x2000 * currblock)
            
            to_read = min(remaining, 0x2000)
            block = self.f.read(to_read)
            if len(block) != to_read:   
                raise Exception()
                
            remaining -= to_read
            data.append(block)
            currblock = self.fragmap[currblock]
            
        data = b"".join(data)
        
        if len(data) != size:
            raise Exception()
        
        return data
            
            
    def scan(self):
        for manif_idx, entry in enumerate(self.manif.entries):
            m_nameptr, m_itemsize, m_fileid, m_dirtype, m_parentidx, m_nextidx, m_firstidx = entry
            if b".lst" in self.manif.filenames[manif_idx]:
                print("prescan manifest entry", m_nameptr, m_itemsize, m_fileid, hex(m_dirtype), m_parentidx, m_nextidx, m_firstidx, self.manif.fullnames[manif_idx])
        
        indexes = {}
        for idx in sorted(self.entries):
            flags, offset, filesize, firstblock, nextblock, prevblock, manif_idx = self.entries[idx]
            
            if b".lst" in self.manif.filenames[manif_idx]:
                print("entry", idx, hex(flags & 0xc007), offset, filesize, firstblock, nextblock, prevblock, manif_idx, self.manif.fullnames[manif_idx])
                m_nameptr, m_itemsize, m_fileid, m_dirtype, m_parentidx, m_nextidx, m_firstidx = self.manif.entries[manif_idx]
                print("       manifest entry", m_nameptr, m_itemsize, m_fileid, hex(m_dirtype), m_parentidx, m_nextidx, m_firstidx)
                
            if manif_idx not in indexes:
                indexes[manif_idx] = []
                
            indexes[manif_idx].append((offset, filesize, firstblock))
            
        print("num indexes", len(indexes))
        exit()
        
        partials = []
        for manif_idx in sorted(indexes):
            # if manif_idx not in self.manif.filesidx:
                # print("missing from manifest", manif_idx)
                # print(self.manif.entries[manif_idx], self.manif.filenames[manif_idx])
                # raise Exception()

            _, itemsize, fileid, dirtype, _, _, _ = self.manif.entries[manif_idx]
            filename = self.manif.fullnames[manif_idx]
            
            parts = []
            for offset, filesize, firstblock in indexes[manif_idx]:
                part = self.read_data(firstblock, filesize)
                parts.append((offset, part))
                
            filedata = bytearray()
            ok = True
            for offset, part in sorted(parts):
                if len(filedata) != offset:
                    print("bad offset", len(filedata), offset)
                    ok = False
                    break
                    
                filedata += part
                
            if self.gotchecksums:
                checksumcount, firstchecksumindex = self.checksummap[fileid]
                if len(filedata) == 0:
                    print("qqqqqqq", checksumcount, firstchecksumindex)
                    
                if checksumcount * 0x8000 < len(filedata):
                    raise Exception()
                    
                for i in range(checksumcount):
                    start = i * 0x8000
                    block = filedata[start:start+0x8000]
                    if len(block) == 0:
                        print("Zero size block")
                        
                    calccrc = (zlib.crc32(block, 0) ^ zlib.adler32(block, 0)) & 0xffffffff
                    crc = self.checksums[firstchecksumindex + i]
                    if calccrc != crc:
                        print("CRC ERROR", fileid, filename, i, len(block), "%08x %08x" % (calccrc, crc))
                    
            if len(filedata) != itemsize:
                print("bad itemsize, gcf has file of size", len(filedata), "but size in manifest is", itemsize)
                print(filedata)
                ok = False
                
            if not ok:
                print("file failed (partial)", filename)
                raise Exception()
                
            else:
                print("file OK", filename)
                
    # def scan_dumb(self):
        # indexes = {}
        # for idx in sorted(self.entries):
            # flags, offset, filesize, firstblock, nextblock, prevblock, manif_idx = self.entries[idx]
            # if manif_idx not in indexes:
                # indexes[manif_idx] = []
                
            # indexes[manif_idx].append((offset, filesize, firstblock))
        
        # fileinfo = []
        # for manif_idx, entry in enumerate(self.manif.entries):
            # _, itemsize, fileid, dirtype, _, _, _= entry
            # filename = self.manif.fullnames[manif_idx]
            
            # if fileid == 0xffffffff:
                # fullname = os.path.join(root, filename)
                # os.makedirs(fullname, exist_ok=True)
                
                # fileinfo.append((fileid, dirtype, filename))
                
            # else:
                # parts = []
                # if manif_idx not in indexes:
                    # print("file failed (missing)", filename)
                    # filedata = b"\x00" * itemsize

                # else:
                    # for offset, filesize, firstblock in indexes[manif_idx]:
                        # part = self.read_data(firstblock, filesize)
                        # parts.append((offset, part))            
                
                    # filedata = b""
                    # ok = True
                    # for offset, part in sorted(parts):
                        # if len(filedata) != offset:
                            # ok = False
                            # break
                            
                        # filedata += part            
                    
                    # if len(filedata) != itemsize:
                        # ok = False
                        
                    # if not ok:
                        # print("file failed (partial)", filename)
                        # filedata = b"\x00" * itemsize
                    
                # fullname = os.path.join(root, filename)
                # os.makedirs(os.path.dirname(fullname), exist_ok=True)
                    
                # if os.path.isfile(fullname):
                    # data2 = open(fullname, "rb").read()
                    # if filedata != data2:
                        # raise Exception("mismatch for file", filename)
                        
                # else:
                    # open(fullname, "wb").write(filedata)
                    
                # fileinfo.append((fileid, dirtype, filename))
            
        # of = open("extracted.txt", "w")
        # for idx, (fileid, dirtype, filename) in enumerate(fileinfo):
            # flags = 0
            # if idx in self.manif.copytable:
                # flags |= 1

            # if idx in self.manif.localtable:
                # flags |= 2
                
            # of.write("flag%d %d %08x %s\n" % (flags, fileid, dirtype, filename.decode("utf8")))
            
        # of.close()
    
gcf = GCF(sys.argv[1])
gcf.scan()

# for fileid in gcf.manif.files:
    # print(gcf.manif.files[fileid])
    
#gcf.scan_dumb()

# f = open(sys.argv[1], "rb")
# manif = Manifest(f)
# for fileid in manif.files:
    # index, filesize, flags, filename = manif.files[fileid]
    # print(fileid, index, filesize, hex(flags), filename)
    