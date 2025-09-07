
import datetime
import struct
import time as time_module


def bytes_as_bool(data: bytes) -> bool:
    return all(b != 0 for b in data)

# Host (IP and Port) encoding and decoding
# Little endian for some reason...
# First four bytes = IP
# Last two bytes = Port

def encode_host(t):
    ip, port = t
    n = tuple(ip.split(".")) + (port)
    return struct.pack("<BBBBH", *n)

def decode_host(data):
    ip = ".".join(str(s) for s in struct.unpack("<BBBB", data[:4]))
    port, = struct.unpack("<H", data[4:])
    return (ip, port)

def py_time(raw_time: int) -> datetime.datetime:
    unix = (raw_time / 1_000_000) - 62135596800
    microseconds = raw_time % 1_000_000
    return datetime.datetime.fromtimestamp(unix) - datetime.timedelta(0, 0, microseconds)


def steam_time(tm) -> int:
    return (time_module.mktime(tm) + 62135596800) * 1_000_000
