# Game Cache File (GCF) Format v6 Specification

This document summarizes the layout of version 6 GCF archives.  It consolidates information from archived copies of the Non-Steam Developer Community and Non-Steam Wiki.

## 1. File Header

```c
struct FileHeader {
    uint32_t HeaderVersion;       // always 1
    uint32_t CacheType;           // 1 for GCF, 2 for NCF
    uint32_t FormatVersion;       // latest known: 6
    uint32_t ApplicationID;       // Steam app ID
    uint32_t ApplicationVersion;  // version of cached app
    uint32_t IsMounted;           // 1 when mounted
    uint32_t Dummy0;              // zero
    uint32_t FileSize;            // total bytes in cache
    uint32_t ClusterSize;         // bytes per cluster
    uint32_t ClusterCount;        // total clusters
    uint32_t Checksum;            // simple byte-sum over prior fields
};
```

* `HeaderVersion` is the structure revision.
* `CacheType` distinguishes GCF and NCF containers.
* `Checksum` adds all bytes in the header except itself.

## 2. Block Allocation Table (BAT)
Maps logical file blocks to physical clusters.  Blocks can represent compressed or encrypted segments of a file.

### Header
```c
struct BlockAllocationTableHeader {
    uint32_t BlockCount;
    uint32_t BlocksUsed;
    uint32_t LastUsedBlock;
    uint32_t Dummy0, Dummy1, Dummy2, Dummy3;
    uint32_t Checksum;            // sum of previous fields
};
```

### Entries
`BlockCount` entries follow the header.
```c
struct BlockAllocationTableEntry {
    uint16_t Flags;               // 0x8000 used, 0x0001 raw, 0x0002 compressed+encrypted,
                                  // 0x0004 encrypted, 0x4000 local-priority (unverified)
    uint16_t Dummy0;
    uint32_t FileDataOffset;      // offset within extracted file
    uint32_t FileDataSize;        // bytes represented by this block
    uint32_t FirstClusterIndex;   // index into FAT
    uint32_t NextBlockIndex;      // next block in chain or BlockCount terminator
    uint32_t PreviousBlockIndex;  // previous block in chain or BlockCount terminator
    uint32_t ManifestIndex;       // file the block belongs to
};
```

## 3. File Allocation Table (FAT)
Provides cluster-to-cluster chaining similar to a disk FAT.

### Header
```c
struct FileAllocationTableHeader {
    uint32_t ClusterCount;        // equals FileHeader.ClusterCount
    uint32_t FirstUnusedEntry;    // index of first free cluster
    uint32_t IsLongTerminator;    // 0 => 0x0000FFFF, 1 => 0xFFFFFFFF terminator
    uint32_t Checksum;            // sum of previous fields
};
```

### Entries
`ClusterCount` entries follow the header.
```c
struct FileAllocationTableEntry {
    uint32_t NextClusterIndex;    // next cluster or terminator
};
```

## 4. Manifest
Holds metadata for all files and directories.

### Header
```c
struct ManifestHeader {
    uint32_t HeaderVersion;       // 4
    uint32_t ApplicationID;
    uint32_t ApplicationVersion;
    uint32_t NodeCount;           // number of manifest nodes
    uint32_t FileCount;           // number of files
    uint32_t CompressionBlockSize;// bytes per compressed/checksum block
    uint32_t BinarySize;          // total bytes of manifest section
    uint32_t NameSize;            // bytes in name table
    uint32_t HashTableKeyCount;   // power-of-two bucket count
    uint32_t NumOfMinimumFootprintFiles;
    uint32_t NumOfUserConfigFiles;
    uint32_t Bitmask;             // misc flags, lower bits describe build/purge/roll
    uint32_t Fingerprint;         // random each build, excluded from checksum
    uint32_t Checksum;            // Adler-32 over manifest with Fingerprint & Checksum zeroed
};
```

### Nodes
`NodeCount` entries describing files and directories.
```c
struct ManifestNode {
    uint32_t NameOffset;          // into name table
    uint32_t CountOrSize;         // child count or file size
    uint32_t FileId;              // 0xFFFFFFFF for directories
    uint32_t Attributes;          // 0x4000 file, 0x0100 encrypted, etc.
    uint32_t ParentIndex;         // 0xFFFFFFFF for root
    uint32_t NextIndex;           // next sibling or 0
    uint32_t ChildIndex;          // first child or 0
};
```

The first node is the root and has an empty name.

### Name Table
`NameSize` bytes of null-terminated UTF‑8 strings referenced by `NameOffset`.

### Hash Table
Two arrays implement a coalesced hash table for quick name lookups:
- `HashTableKeys[HashTableKeyCount]` – bucket heads storing indices into `HashTableIndices` or `0xFFFFFFFF` when empty.
- `HashTableIndices[NodeCount]` – chain nodes; high bit marks end of bucket.  Lower 31 bits store a `ManifestNode` index.

### Minimum Footprint Files
Array of `ManifestMinimumFootprintEntry { uint32_t NodeIndex; }`.  Listed files should always exist on disk.

### User Config Files
Array of `ManifestUserConfigEntry { uint32_t NodeIndex; }`.  Local versions override cache copies.

## 5. Manifest Map
Maps manifest nodes to their first block in the BAT.

```c
struct ManifestMapHeader {
    uint32_t HeaderVersion;   // 1
    uint32_t Dummy0;          // 0
};

struct ManifestMapEntry {
    uint32_t FirstBlockIndex; // BlockCount if not stored or directory
};
```

`NodeCount` `ManifestMapEntry` structures follow the header.

## 6. Checksums
Provides integrity information and optional RSA signature.

```c
struct ChecksumDataContainer {
    uint32_t HeaderVersion;   // 1
    uint32_t ChecksumSize;    // bytes of checksum data following
};
```

Multiple tables may appear inside the container.  Each table begins with a `FileIdChecksumTableHeader` describing the layout and counts, followed by per‑file checksum records.  The checksum for a block is `adler32(data) ^ crc32(data)`.

At the end of the checksum data is an RSA signature:
```c
struct ChecksumSignature {
    uint8_t Signature[0x80];  // PKCS#1 v1.5 using SHA‑1
};
```
A trailing `LatestApplicationVersion { uint32_t ApplicationVersion; }` indicates the newest version for which the checksums apply.

## 7. Data Section
Physical file data stored in clusters.
```c
struct DataHeader {
    uint32_t ClusterCount;   // equals FileHeader.ClusterCount
    uint32_t ClusterSize;    // equals FileHeader.ClusterSize
    uint32_t FirstClusterOffset;
    uint32_t ClustersUsed;
    uint32_t Checksum;       // sum of prior fields
};
```
Clusters begin at `FirstClusterOffset` and are linked via the FAT.

---

*References: archived pages from developer.505.ru and singularity.us.to (Non‑Steam community documentation).* 
