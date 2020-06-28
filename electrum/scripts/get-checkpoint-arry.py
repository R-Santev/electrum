#!/usr/bin/env python

from json import loads, dumps
from sys import exit, argv
import base64
import urllib.request, urllib.error, urllib.parse
from urllib.error import HTTPError

from electrum import constants
from struct import unpack_from, unpack
from electrum.equihash import is_gbp_valid

if len(argv) < 2:
    print('Arguments: <begin_block>')
    sys.exit(1)

def averaging_window_timespan():
    return constants.net.DIGI_AVERAGING_WINDOW * constants.net.POW_TARGET_SPACING

def min_actual_timespan():
    return (averaging_window_timespan() * (100 - constants.net.DIGI_MAX_ADJUST_UP)) // 100

def max_actual_timespan():
    return (averaging_window_timespan() * (100 + constants.net.DIGI_MAX_ADJUST_DOWN)) // 100

def is_post_btg_fork(height):
    return height >= constants.net.BTG_HEIGHT

def is_post_equihash_fork(height):
    return height >= constants.net.EQUIHASH_FORK_HEIGHT

def needs_retarget(height):
    return is_post_btg_fork(height) or (height % difficulty_adjustment_interval() == 0)


def difficulty_adjustment_interval():
    return constants.net.POW_TARGET_TIMESPAN_LEGACY // constants.net.POW_TARGET_SPACING

def get_header_size(height):
    size = constants.net.HEADER_SIZE_LEGACY

    if is_post_btg_fork(height):
        solution_size = get_equihash_params(height).get_solution_size()
        solution_size_compact = len(var_int(solution_size)) // 2 - 1
        size += solution_size_compact + solution_size

    return size

def get_equihash_params(height):
    return constants.net.EQUIHASH_PARAMS if height < constants.net.EQUIHASH_FORK_HEIGHT \
        else constants.net.EQUIHASH_PARAMS_FORK

def var_int(i):
    # https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
    if i < 0xfd:
        return int_to_hex(i)
    elif i <= 0xffff:
        return "fd"+int_to_hex(i, 2)
    elif i <= 0xffffffff:
        return "fe"+int_to_hex(i, 4)
    else:
        return "ff"+int_to_hex(i, 8)


def var_int_read(value, start):
    size = value[start]
    start += 1

    if size == 253:
        (size,) = unpack_from('<H', value, start)
        start += 2
    elif size == 254:
        (size,) = unpack_from('<I', value, start)
        start += 4
    elif size == 255:
        (size,) = unpack_from('<Q', value, start)
        start += 8

    return start, size


def uint256_from_bytes(s):
    r = 0
    t = unpack("<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r


def get_target(height, headers=None):
    print('get target of block ', height)
    if headers is None:
        headers = {}

    # Check for genesis
    if height == 0:
        new_target = constants.net.POW_LIMIT_LEGACY
    # Check for valid checkpoint
    # elif height % difficulty_adjustment_interval() == 0 and 0 <= ((height // difficulty_adjustment_interval()) - 1) < len(checkpoints):
    #     h, t = checkpoints[((height // difficulty_adjustment_interval()) - 1)]
    #     new_target = t
    # Check for prefork
    elif height < constants.net.BTG_HEIGHT:
        new_target = get_legacy_target(height, headers)
    # Premine
    elif height < constants.net.BTG_HEIGHT + constants.net.PREMINE_SIZE:
        new_target = constants.net.POW_LIMIT
    # Initial start of BTG Fork (reduced difficulty)
    elif height < constants.net.BTG_HEIGHT + constants.net.PREMINE_SIZE + constants.net.DIGI_AVERAGING_WINDOW:
        new_target = constants.net.POW_LIMIT_START
    # Digishield
    elif height < constants.net.LWMA_HEIGHT:
        new_target = get_digishield_target(height, headers)
    # Zawy LWMA (old)
    elif height < constants.net.EQUIHASH_FORK_HEIGHT:
        new_target = get_lwma_target(height, headers, constants.net.LWMA_ADJUST_WEIGHT_LEGACY,
                                            constants.net.LWMA_MIN_DENOMINATOR_LEGACY)
    # Initial start of BTG Equihash Fork (reduced difficulty)
    elif height < constants.net.EQUIHASH_FORK_HEIGHT + constants.net.LWMA_AVERAGING_WINDOW:
        last = get_header((height - 1), headers)
        bits = last.get('bits')
        new_target = (bits)

        if height == constants.net.EQUIHASH_FORK_HEIGHT:
            # reduce diff
            new_target *= 100

            if new_target > constants.net.POW_LIMIT:
                new_target = constants.net.POW_LIMIT
    # Zawy LWMA (new)
    else:
        new_target = get_lwma_target(height, headers, constants.net.LWMA_ADJUST_WEIGHT,
                                            constants.net.LWMA_MIN_DENOMINATOR)

    return new_target

def get_legacy_target(height, headers):
    last_height = (height - 1)
    last = get_header(last_height, headers)

    if constants.net == constants.BitcoinGoldRegtest:
        new_target = bits_to_target(last.get('bits'))
    elif height % difficulty_adjustment_interval() != 0:
        if constants.net == constants.BitcoinGoldTestnet:
            cur = get_header(height, headers)

            # Special testnet handling
            if cur.get('timestamp') > last.get('timestamp') + constants.net.POW_TARGET_SPACING * 2:
                new_target = constants.net.POW_LIMIT_LEGACY
            else:
                # Return the last non-special-min-difficulty-rules-block
                prev_height = last_height - 1
                prev = get_header(prev_height, headers)

                while prev is not None and last.get('block_height') % difficulty_adjustment_interval() != 0 \
                        and last.get('bits') == constants.net.POW_LIMIT:
                    last = prev
                    prev_height -= 1
                    prev = get_header(prev_height, headers)

                new_target = bits_to_target(last.get('bits'))
        else:
            new_target = bits_to_target(last.get('bits'))
    else:
        first = read_header(height - difficulty_adjustment_interval())
        target = bits_to_target(last.get('bits'))

        actual_timespan = last.get('timestamp') - first.get('timestamp')
        target_timespan = constants.net.POW_TARGET_TIMESPAN_LEGACY
        actual_timespan = max(actual_timespan, target_timespan // 4)
        actual_timespan = min(actual_timespan, target_timespan * 4)

        new_target = min(constants.net.POW_LIMIT_LEGACY, (target * actual_timespan) // target_timespan)

    return new_target

def get_lwma_target(height, headers, weight, denominator):
    cur = get_header(height, headers)
    last_height = (height - 1)
    last = get_header(last_height, headers)

    # Special testnet handling
    if constants.net == constants.BitcoinGoldRegtest:
        new_target = bits_to_target(last.get('bits'))
    elif constants.net == constants.BitcoinGoldTestnet and cur.get('timestamp') > last.get('timestamp') + constants.net.POW_TARGET_SPACING * 2:
        new_target = constants.net.POW_LIMIT
    else:
        total = 0
        t = 0
        j = 0

        assert (height - constants.net.LWMA_AVERAGING_WINDOW) > 0

        ts = 6 * constants.net.POW_TARGET_SPACING

        # Loop through N most recent blocks.  "< height", not "<=".
        # height-1 = most recently solved block
        for i in range(height - constants.net.LWMA_AVERAGING_WINDOW, height):
            cur = get_header(i, headers)
            prev_height = (i - 1)
            prev = get_header(prev_height, headers)

            solvetime = cur.get('timestamp') - prev.get('timestamp')

            if constants.net.LWMA_SOLVETIME_LIMITATION and solvetime > ts:
                solvetime = ts

            j += 1
            t += solvetime * j
            total += bits_to_target(cur.get('bits')) // (weight * constants.net.LWMA_AVERAGING_WINDOW * constants.net.LWMA_AVERAGING_WINDOW)

        # Keep t reasonable in case strange solvetimes occurred.
        if t < constants.net.LWMA_AVERAGING_WINDOW * weight // denominator:
            t = constants.net.LWMA_AVERAGING_WINDOW * weight // denominator

        new_target = t * total

        if new_target > constants.net.POW_LIMIT:
            new_target = constants.net.POW_LIMIT

    return new_target

def get_digishield_target(height, headers):
    pow_limit = constants.net.POW_LIMIT
    height -= 1
    last = get_header(height, headers)

    if last is None:
        new_target = pow_limit
    elif constants.net == constants.BitcoinGoldRegtest:
        new_target = bits_to_target(last.get('bits'))
    else:
        first = last
        total = 0
        i = 0

        while i < constants.net.DIGI_AVERAGING_WINDOW and first is not None:
            total += bits_to_target(first.get('bits'))
            prev_height = height - i - 1
            first = get_header(prev_height, headers)
            i += 1

        # This should never happen else we have a serious problem
        assert first is not None

        avg = total // constants.net.DIGI_AVERAGING_WINDOW
        actual_timespan = get_mediantime_past(headers, last.get('block_height')) \
            - get_mediantime_past(headers, first.get('block_height'))

        if actual_timespan < min_actual_timespan():
            actual_timespan = min_actual_timespan()

        if actual_timespan > max_actual_timespan():
            actual_timespan = max_actual_timespan()

        avg = avg // averaging_window_timespan()
        avg *= actual_timespan

        if avg > pow_limit:
            avg = pow_limit

        new_target = int(avg)

    return new_target

def get_mediantime_past(headers, start_height):
    header = get_header(start_height, headers)

    times = []
    i = 0

    while i < 11 and header is not None:
        times.append(header.get('timestamp'))
        prev_height = start_height - i - 1
        header = get_header(prev_height, headers)
        i += 1

    times.sort()
    return times[(len(times) // 2)]

def bits_to_target(bits: int) -> int:
    size = bits >> 24
    word = bits & 0x007fffff

    if size <= 3:
        word >>= 8 * (3 - size)
        ret = word
    else:
        ret = word
        ret <<= 8 * (size - 3)

    return ret

def target_to_bits(target: int) -> int:
    assert target >= 0
    nsize = (target.bit_length() + 7) // 8
    if nsize <= 3:
        c = target << (8 * (3 - nsize))
    else:
        c = target >> (8 * (nsize - 3))
    if c & 0x00800000:
        c >>= 8
        nsize += 1
    assert (c & ~0x007fffff) == 0
    assert nsize < 256
    c |= nsize << 24
    return c

def rpc(method, params):
    data = {
        "jsonrpc": "1.0",
        "id":"1",
        "method": method,
        "params": params
    }

    data_json = dumps(data)
    username = <rpc user>
    password = <rpc password>
    port = <rpc port>

    url = "http://<daemon url>:{}/".format(port)
    req = urllib.request.Request(url, data_json.encode("utf-8"), {'content-type': 'application/json'})

    base64string = base64.encodestring(('%s:%s' % (username, password)).encode()).decode().replace('\n', '')
    req.add_header("Authorization", "Basic %s" % base64string)

    try:
        response_stream = urllib.request.urlopen(req)
    except HTTPError as e:
        content = e.read()
        print('error content: ', content)
        return None

    json_response = response_stream.read()

    return loads(json_response)

def checkpoints():
        return constants.net.CHECKPOINTS

def get_header_from_block(block):

    header = {
		'version': block['version'],
		'prev_block_hash': block['previousblockhash'],
		'merkle_root': block['merkleroot'],
		'block_height': block['height'],
		'reserved': '00000000000000000000000000000000000000000000000000000000',
		'timestamp': block['time'],
		'bits': int(block['bits'], 16),
		'nonce': block['nonce'],
		'solution':block['solution']
	}

    return header

def read_header(height: int) -> None:
    print('read header of block ', height)
    h = rpc('getblockhash', [height])['result']
    block = rpc('getblock', [h])['result']

    return get_header_from_block(block)

def get_header(height : int, headers=None) -> None:
    return read_header(height)

def get_block(height: int) -> None:
    print('read block at height: ', height)
    h = rpc('getblockhash', [height])['result']
    block = rpc('getblock', [h])['result']
    
    return block

i = int(argv[1])
INTERVAL = 2016 # Electrum checkpoints are blocks 2015, 2015 + 2016, 2015 + 2016*2, ...

block_count = int(rpc('getblockcount', [])['result'])
print(('Network latest block: {}'.format(block_count)))
while True:
    try:
        block = get_block(i)
        cp = [
            block['hash'],
            get_target(i, get_header_from_block(block))
        ]

        with open('checkpoints_output.json', 'a+') as f:
            f.write(dumps(cp, indent=4, separators=(',', ':')) + ',')
            
        i += INTERVAL
        if i > block_count:
            print('Done.')
            break
    except:
        print('error occured during handle block ', i, 'please restart with this block')
        break

