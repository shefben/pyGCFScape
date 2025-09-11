import io, struct, zlib

import bobhash

class Manifest:
    def __init__(self, f, adjust_size=False):
        header_data = f.read(56)

        (   self.version,
            self.appid,
            self.appver,
            self.itemcount,
            self.filecount,
            self.blocksize,
            self.storedsize,
            self.namesize,
            self.htcount,
            self.copycount,
            self.localcount,
            self.flags,
            self.fingerprint,
            self.csum ) = struct.unpack("<14I", header_data)
            
        if self.version not in (3, 4):
            raise Exception("unsupported version", self.version)
            
        print("manifest version", self.version)
        print("itemcount", self.itemcount)

        # for some reason, when inside a GCF, early versions of Steam append a table at the end of the manifest and adjust the size
        self.realsize = 56 + self.itemcount * 28 + self.namesize + (self.itemcount + self.htcount + self.copycount + self.localcount) * 4

        # we read the rest of the data based on the calculated size instead
        data = f.read(self.realsize - 56)

        self.fulldata = header_data + data
        
        if self.storedsize != self.realsize:
            if self.storedsize != self.realsize + self.itemcount * 4:
                raise Exception("extra size does not match itemcount")

            if not adjust_size:
                raise Exception("manifest got extra table but adjustment not enabled")
                
            if self.version != 3:
                raise Exception("manifest got extra table but version is not 3")
            
            # adjust the fulldata to contain the real manifest size
            self.fulldata = self.fulldata[:0x18] + struct.pack("<I", self.realsize) + self.fulldata[0x1c:]
            
            self.adjusted = True
            
        else:
            self.adjusted = False
            
        # crop out checksum and fingerprint before calculating checksum
        csumdata = self.fulldata[:0x30] + b"\x00" * 8 + self.fulldata[0x38:]

        calc_csum = zlib.adler32(csumdata, 0) & 0xffffffff
        if self.csum != calc_csum:
            raise Exception("bad checksum")
            
        bio = io.BytesIO(data)
            
        self.entries = []
        for i in range(self.itemcount):
            entry = struct.unpack("<7I", bio.read(28))
            self.entries.append(entry)
            
        self.filenamedata = bio.read(self.namesize)

        self.hashtable = []
        for i in range(self.htcount + self.itemcount):
            self.hashtable.append(struct.unpack("<I", bio.read(4))[0])

        self.copytable = []
        for i in range(self.copycount):
            self.copytable.append(struct.unpack("<I", bio.read(4))[0])

        self.localtable = []
        for i in range(self.localcount):
            self.localtable.append(struct.unpack("<I", bio.read(4))[0])

        if len(bio.read()) != 0:
            raise Exception("unconsumed manifest data")

        self.filenames = []
        self.fullnames = []

        dircontent = {}
        for idx, entry in enumerate(self.entries):
            nameptr, itemsize, fileid, dirtype, parentidx, nextidx, firstidx = entry
            if fileid == 0xffffffff:
                dircontent[idx] = []
        
        for nameptr, itemsize, fileid, dirtype, parentidx, nextidx, firstidx in self.entries:
            end = self.filenamedata.index(b"\x00", nameptr)
            self.filenames.append(self.filenamedata[nameptr:end])

        self.files = {}
        for idx, entry in enumerate(self.entries):
            nameptr, itemsize, fileid, dirtype, parentidx, nextidx, firstidx = entry

            # error in 10501_4.manifest
            # 4GB+ in 12401_0.manifest ?
            if fileid == 0xffffffff and dirtype != 0:
                print("---", idx, entry)
                raise Exception("fileid not set but dirtype is set")
            
            filename = self.filenames[idx]
            
            # some 4gb workaround?
            if len(filename) == 0 and idx != 0:
                print(filename, idx, entry)
                #raise Exception()
                continue

            h = bobhash.bobhash(filename.lower())
            mask = self.htcount - 1
            hpos = self.hashtable[h & mask]
            if hpos == 0xffffffff:
                raise Exception("bad hash")
                
            found = False
            while True:
                cand_id = self.hashtable[hpos]
                
                if cand_id & 0x7fffffff == idx:
                    #print("found", idx)
                    found = True
                    break
                    
                if cand_id & 0x80000000:
                    break
                    
                hpos += 1
                
            if not found:
                raise Exception("bad hash")
            
            tempidx = parentidx
            while tempidx != 0xffffffff:
                filename = self.filenames[tempidx] + b"\\" + filename
                tempidx = self.entries[tempidx][4]


            if parentidx != 0xffffffff:
                dircontent[parentidx].append(idx)
                
            #print("---", idx, nameptr, itemsize, fileid, dirtype, parentidx, nextidx, firstidx, filename)

            if filename[0:1] != b"\\" and idx != 0:
                raise Exception(filename, idx, entry)
                
            filename = filename[1:]
            
            self.fullnames.append(filename)
                    
            if fileid != 0xffffffff:
                if fileid in self.files:
                    raise Exception("Duplicate fileid")
                    
                self.files[fileid] = (idx, itemsize, dirtype, filename)
            
            
        for idx, entry in enumerate(self.entries):
            nameptr, itemsize, fileid, dirtype, parentidx, nextidx, firstidx = entry
            
            if fileid == 0xffffffff:
                #print(idx, entry, self.fullnames[idx])
                if itemsize != len(dircontent[idx]):
                    raise Exception(itemsize, len(dircontent[idx]))

                # for directories, firstidx points to the first entry, or 0 if dir is empty
                if firstidx != 0:
                    if firstidx != dircontent[idx][0]:
                        raise Exception(idx, entry)
                    
                else:
                    if itemsize != 0:
                        raise Exception()
                        
            else:
                # for files, firstidx is either 0 or 0xffffffff (not sure what decides which, but seems to be the same for all files within a manifest)
                if firstidx not in (0, 0xffffffff):
                    print(idx, entry, filename)
                    raise Exception()
                
            if parentidx != 0xffffffff:
                # nextidx points to next file in dir
                if nextidx not in (0, 0xffffffff):
                    pos = dircontent[parentidx].index(idx)
                    if dircontent[parentidx][pos + 1] != nextidx:
                        raise Exception("DSDSD", idx, entry)
                    
            