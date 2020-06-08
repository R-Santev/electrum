
bfh = bytes.fromhex


def bh2u(x: bytes) -> str:
    """
    str with hex representation of a bytes-like object

    >>> x = bytes((1, 2, 10))
    >>> bh2u(x)
    '01020A'
    """
    return x.hex()

def rev_hex(s: str) -> str:
    return bh2u(bfh(s)[::-1])


def int_to_hex(i: int, length: int=1) -> str:
    """Converts int to little-endian hex string.
    `length` is the number of bytes available
    """
    if not isinstance(i, int):
        raise TypeError('{} instead of int'.format(i))
    range_size = pow(256, length)
    if i < -(range_size//2) or i >= range_size:
        raise OverflowError('cannot convert int {} to hex ({} bytes)'.format(i, length))
    if i < 0:
        # two's complement
        i = range_size + i
    s = hex(i)[2:].rstrip('L')
    s = "0"*(2*length - len(s)) + s
    return rev_hex(s)

def hash_encode(x: bytes) -> str:
    return bh2u(x[::-1])
    
def serialize_header(header_dict: dict) -> str:
    s = int_to_hex(header_dict['version'], 4) \
        + rev_hex(header_dict['prev_block_hash']) \
        + rev_hex(header_dict['merkle_root'])

    # not legacy block
    if header_dict.get('block_height') >= 1:
        s += int_to_hex(header_dict.get('block_height'), 4) \
            + rev_hex(header_dict.get('reserved'))
    
    s += int_to_hex(header_dict.get('timestamp'), 4) \
        + int_to_hex(header_dict.get('bits'), 4)
    
    # legacy block
    if header_dict.get('block_height') < 1:
        s += rev_hex(header_dict.get('nonce'))[:8]
    else:
        s += rev_hex(header_dict.get('nonce')) \
             + rev_hex(header_dict.get('solution'))

    return s

def deserialize_header(s: bytes, height: int) -> dict:
    if not s:
        return

    # original blok
    if height < 1:
        if len(s) != 80:
            return None
    else:
        if len(s) < 140:
            return None
    
    hex_to_int = lambda s: int.from_bytes(s, byteorder='little')
    h = {}
    h['block_height'] = height
    h['version'] = hex_to_int(s[0:4])
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])

    # original block
    if height < 1:
        h['timestamp'] = hex_to_int(s[68:72])
        h['bits'] = hex_to_int(s[72:76])
        h['nonce'] = hex_to_int(s[76:80])
    else:
        h['reserved'] = hash_encode(s[72:100])
        h['timestamp'] = hex_to_int(s[100:104])
        h['bits'] = hex_to_int(s[104:108])
        h['nonce'] = hex_to_int(s[108:140])
        h['solution'] = hash_encode(s[140:])

    return h
    
# All block header data below are from Bitcoin Gold testnet
def dump_78190() -> str:
	header = {
		'version': 536870912,
		'prev_block_hash': '0006670b8b876c13f847b5b190097bec8f225b948b8a4dc4a52246324c225815',
		'merkle_root': 'bfb0f27df25d67a12c8088db1470cb644603e21d8c9fb22b3277fca75f8fd076',
		'block_height': 78190,
		'reserved': '00000000000000000000000000000000000000000000000000000000',
		'timestamp': 1591182462,
		'bits': 0x1f07ffff,
		'nonce': '0000052f0000000000000000000000000000000000000000000000000003168f',
		'solution':'141ad6110bc7cd252f7f15ea33f4da474d2cb935c136bf8e9946515cb577d2d5e6252efb6b06b56a54e9d92a81152f76bff21a9c723855f35d7c05dccea532407a1eb796e0e9a3c9d4f9a647a9e1d5090059fc213f3b6997ec110f0d1462919411bd5434'
	}

	return serialize_header(header)


def dump_78191() -> str:
	header = {
		'version': 536870912,
		'prev_block_hash': '0001e3b67be015ee30ad46ef53fd273807af43847e399d25b5aee784ad36ae28',
		'merkle_root': '4aed2ab8d5da31cbf4007c22d004a59bf6b82048481d8dfd235f34ecb5addc1e',
		'block_height': 78191,
		'reserved': '00000000000000000000000000000000000000000000000000000000',
		'timestamp': 1591185960,
		'bits': 0x1f07ffff,
		'nonce': '000000480000000000000000000000000000000000000000000000000007168f',
		'solution':'075c778555fc06bbc73fca0dd1e26a8b4e8bfccf14592cd83954ef6131c1ceddd6d298496a86cc2b86c9a68a9b5c7b7a63233584f6e6a998b2a5f3bf1634239762bca16365db2eff7019d6684383ff50711a3ec791174ad7fc70f60e394a232c6971a55e'
	}
	
	return serialize_header(header)
		
		
def dump_78192() -> str:
	header = {
		'version': 536870912,
		'prev_block_hash': '0002542468c9827fc1b310cd92df8f3b02704fec256834baec4cc2de36b6ada2',
		'merkle_root': 'e1500a34006a7cec807f52b487a564fe447a1dcd7388be1a00e0bfc62c6192eb',
		'block_height': 78192,
		'reserved': '00000000000000000000000000000000000000000000000000000000',
		'timestamp': 1591188771,
		'bits': 0x1f07ffff,
		'nonce': '000005bf000000000000000000000000000000000000000000000000000a168f',
		'solution':'0ec1397e1de32303551857579402acbbe0a0beafdaff7e7959204dc5a7bb471d77c8da095353b2338647e0c69423fbfabe0610cea64fcca6c587f67797148a7a3e3717f8ef2cb395d48d7c55966a3b3e7f6646acfb7fc9a5a04f577829c706f9f9cdd963'
	}
	
	return serialize_header(header)
	
	
if __name__ == '__main__':
	print('============ 78190 =============')
	print(dump_78190())
	print(deserialize_header(bfh(dump_78190()), 78190)['block_height'] == 78190)
	print('============ 78191 =============')
	print(dump_78191())
	print(deserialize_header(bfh(dump_78191()), 78191)['block_height'] == 78191)
	print('============ 78192 =============')
	print(dump_78192())
	print(deserialize_header(bfh(dump_78192()), 78192)['block_height'] == 78192)
 
