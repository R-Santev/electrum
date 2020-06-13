# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import threading
import time
from typing import Optional, Dict, Mapping, Sequence
from .header_storage import HeaderStorage
from . import util
from .bitcoin import hash_encode, int_to_hex, rev_hex
from .crypto import sha256d
from . import constants
from .util import bfh, bh2u, to_bytes
from .simple_config import SimpleConfig
from .logging import get_logger, Logger


_logger = get_logger(__name__)

HEADER_SIZE = 80  # bytes
MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000


class MissingHeader(Exception):
    pass

class InvalidHeader(Exception):
    pass

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

def serialize_header(header_dict: dict) -> str:
    s = int_to_hex(header_dict['version'], 4) \
        + rev_hex(header_dict['prev_block_hash']) \
        + rev_hex(header_dict['merkle_root'])

    # not legacy block
    if header_dict.get('block_height') >= constants.net.BTG_HEIGHT:
        s += int_to_hex(header_dict.get('block_height'), 4) \
            + rev_hex(header_dict.get('reserved'))
    
    s += int_to_hex(header_dict.get('timestamp'), 4) \
        + int_to_hex(header_dict.get('bits'), 4)
    
    # legacy block
    if header_dict.get('block_height') < constants.net.BTG_HEIGHT:
        # Bitcoin header nonce is 32 bits
        s += rev_hex(header_dict.get('nonce'))[:8]
    else:
        # Bitcoin Gold header nonce is 256 bits
        s += rev_hex(header_dict.get('nonce')) \
             + rev_hex(header_dict.get('solution'))

    return s

def deserialize_header(s: bytes, height: int) -> dict:
    if not s:
        raise InvalidHeader('Invalid header: {}'.format(s))

    # original blok
    if height < constants.net.BTG_HEIGHT:
        if len(s) != constants.net.HEADER_SIZE_ORIGIN:
            raise InvalidHeader('Invalid header length: {}'.format(len(s)))
    else:
        if len(s) < constants.net.HEADER_SIZE_LEGACY:
            raise InvalidHeader('Invalid header length: {}'.format(len(s)))
    
    hex_to_int = lambda s: int.from_bytes(s, byteorder='little')
    h = {}
    h['block_height'] = height
    h['version'] = hex_to_int(s[0:4])
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])

    # original block
    if height < constants.net.BTG_HEIGHT:
        h['timestamp'] = hex_to_int(s[68:72])
        h['bits'] = hex_to_int(s[72:76])
        h['nonce'] = hash_encode(s[76:80])
    else:
        h['reserved'] = hash_encode(s[72:100])
        h['timestamp'] = hex_to_int(s[100:104])
        h['bits'] = hex_to_int(s[104:108])
        h['nonce'] = hash_encode(s[108:140])
        h['solution'] = hash_encode(s[140:])
    
    return h

def hash_header(header: dict) -> str:
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_raw_header(serialize_header(header))


def hash_raw_header(header: str) -> str:
    return hash_encode(sha256d(bfh(header)))

# key: blockhash hex at forkpoint
# the chain at some key is the best chain that includes the given hash
blockchains = {}  # type: Dict[str, Blockchain]
blockchains_lock = threading.RLock()  # lock order: take this last; so after Blockchain.lock


def read_blockchains(config: 'SimpleConfig'):
    best_chain = Blockchain(config=config,
                            forkpoint=constants.net.max_checkpoint(),
                            parent=None,
                            forkpoint_hash=constants.net.get_checkpoint_hash(constants.net.max_checkpoint()),
                            prev_hash=None)
    best_chain.save_header(constants.net.MAX_CHECKPOINT_HEADER)
    blockchains[constants.net.get_checkpoint_hash(constants.net.max_checkpoint())] = best_chain
    # consistency checks
    if best_chain.height() > constants.net.max_checkpoint():
        header_after_cp = best_chain.read_header(constants.net.max_checkpoint()+1)
        if not header_after_cp or not best_chain.can_connect(header_after_cp, check_height=False):
            _logger.info("[blockchain] deleting best chain. cannot connect header after last cp to last cp.")
            os.unlink(best_chain.path())
            best_chain.update_size()
    # forks
    fdir = os.path.join(util.get_headers_dir(config), 'forks')
    util.make_dir(fdir)
    # files are named as: fork2_{forkpoint}_{prev_hash}_{first_hash}
    l = filter(lambda x: x.startswith('fork2_') and '.' not in x, os.listdir(fdir))
    l = sorted(l, key=lambda x: int(x.split('_')[1]))  # sort by forkpoint

    def delete_chain(filename, reason):
        _logger.info(f"[blockchain] deleting chain {filename}: {reason}")
        if os.path.isdir(os.path.join(fdir, filename)):  # maybe leveldb data dir
            os.rmdir(os.path.join(fdir, filename))
        else:
            os.unlink(os.path.join(fdir, filename))

    def instantiate_chain(filename):
        __, forkpoint, prev_hash, first_hash = filename.split('_')
        forkpoint = int(forkpoint)
        prev_hash = (64-len(prev_hash)) * "0" + prev_hash  # left-pad with zeroes
        first_hash = (64-len(first_hash)) * "0" + first_hash
        # forks below the max checkpoint are not allowed
        if forkpoint <= constants.net.max_checkpoint():
            delete_chain(filename, "deleting fork below max checkpoint")
            return
        # find parent (sorting by forkpoint guarantees it's already instantiated)
        for parent in blockchains.values():
            if parent.check_hash(forkpoint - 1, prev_hash):
                break
        else:
            delete_chain(filename, "cannot find parent for chain")
            return
        b = Blockchain(config=config,
                       forkpoint=forkpoint,
                       parent=parent,
                       forkpoint_hash=first_hash,
                       prev_hash=prev_hash)
        # consistency checks
        h = b.read_header(b.forkpoint)
        if first_hash != hash_header(h):
            delete_chain(filename, "incorrect first hash for chain")
            return
        if not b.parent.can_connect(h, check_height=False):
            delete_chain(filename, "cannot connect chain to parent")
            return
        chain_id = b.get_id()
        assert first_hash == chain_id, (first_hash, chain_id)
        blockchains[chain_id] = b

    for filename in l:
        instantiate_chain(filename)


def get_best_chain() -> 'Blockchain':
    return blockchains[constants.net.get_checkpoint_hash(constants.net.max_checkpoint())]

# block hash -> chain work; up to and including that block
_CHAINWORK_CACHE = {
    "0000000000000000000000000000000000000000000000000000000000000000": 0,  # virtual block at height -1
}  # type: Dict[str, int]


def init_headers_file_for_best_chain():
    b = get_best_chain()
    with b.lock:
        b.update_size()


class Blockchain(Logger):
    """
    Manages blockchain headers and their verification
    """
    def __init__(self, config: SimpleConfig, forkpoint: int, parent: Optional['Blockchain'],
                 forkpoint_hash: str, prev_hash: Optional[str]):

        assert isinstance(forkpoint_hash, str) and len(forkpoint_hash) == 64, forkpoint_hash
        assert (prev_hash is None) or (isinstance(prev_hash, str) and len(prev_hash) == 64), prev_hash
        # assert (parent is None) == (forkpoint == 0)
        if 0 < forkpoint < constants.net.max_checkpoint():
            raise Exception(f"cannot fork below max checkpoint. forkpoint: {forkpoint}")
        Logger.__init__(self)
        self.config = config
        self.forkpoint = forkpoint  # height of first header
        self._height = forkpoint # latest height of current chain
        self.parent = parent
        self._forkpoint_hash = forkpoint_hash  # blockhash at forkpoint. "first hash"
        self._prev_hash = prev_hash  # blockhash immediately before forkpoint
        self.lock = threading.RLock()
        self.headerdb = HeaderStorage(self.path())
        self.update_size()

    @property
    def checkpoints(self):
        return constants.net.CHECKPOINTS

    def get_max_child(self) -> Optional[int]:
        children = self.get_direct_children()
        return max([x.forkpoint for x in children]) if children else None

    def get_max_forkpoint(self) -> int:
        """Returns the max height where there is a fork
        related to this chain.
        """
        mc = self.get_max_child()
        return mc if mc is not None else self.forkpoint

    def get_direct_children(self) -> Sequence['Blockchain']:
        with blockchains_lock:
            return list(filter(lambda y: y.parent==self, blockchains.values()))

    def get_parent_heights(self) -> Mapping['Blockchain', int]:
        """Returns map: (parent chain -> height of last common block)"""
        with self.lock, blockchains_lock:
            result = {self: self.height()}
            chain = self
            while True:
                parent = chain.parent
                if parent is None: break
                result[parent] = chain.forkpoint - 1
                chain = parent
            return result

    def get_height_of_last_common_block_with_chain(self, other_chain: 'Blockchain') -> int:
        last_common_block_height = 0
        our_parents = self.get_parent_heights()
        their_parents = other_chain.get_parent_heights()
        for chain in our_parents:
            if chain in their_parents:
                h = min(our_parents[chain], their_parents[chain])
                last_common_block_height = max(last_common_block_height, h)
        return last_common_block_height

    @with_lock
    def get_branch_size(self) -> int:
        return self.height() - self.get_max_forkpoint() + 1

    def get_name(self) -> str:
        return self.get_hash(self.get_max_forkpoint()).lstrip('0')[0:10]

    def check_header(self, header: dict) -> bool:
        header_hash = hash_header(header)
        height = header.get('block_height')
        return self.check_hash(height, header_hash)     

    def check_hash(self, height: int, header_hash: str) -> bool:
        """Returns whether the hash of the block at given height
        is the given hash.
        """
        assert isinstance(header_hash, str) and len(header_hash) == 64, header_hash  # hex
        try:
            return header_hash == self.get_hash(height)
        except Exception:
            return False

    def fork(parent, header: dict) -> 'Blockchain':
        if not parent.can_connect(header, check_height=False):
            raise Exception("forking header does not connect to parent chain")
        forkpoint = header.get('block_height')
        self = Blockchain(config=parent.config,
                          forkpoint=forkpoint,
                          parent=parent,
                          forkpoint_hash=hash_header(header),
                          prev_hash=parent.get_hash(forkpoint-1))
        self.assert_headers_file_available(parent.path())
        self.save_header(header)
        # put into global dict. note that in some cases
        # save_header might have already put it there but that's OK
        chain_id = self.get_id()
        with blockchains_lock:
            blockchains[chain_id] = self
        return self

    @with_lock
    def height(self) -> int:
        # return self.headerdb.get_latest()
        return self._height

    # @with_lock
    # def size(self) -> int:
    #     return self._size

    @with_lock
    def update_size(self) -> None:
        latest = self.headerdb.get_latest()
        # restore _height if this is not the first time runing
        if latest != 0 and latest > self.forkpoint:
            self._height = latest

    def verify_header(cls, header: dict, prev_hash: str, target: int, expected_header_hash: str=None) -> None:
        _hash = hash_header(header)
        if expected_header_hash and expected_header_hash != _hash:
            raise Exception("hash mismatches with expected: {} vs {}".format(expected_header_hash, _hash))
        if prev_hash != header.get('prev_block_hash'):
            raise Exception("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if constants.net == constants.BitcoinGoldTestnet or constants.net == constants.BitcoinGoldRegtest:
            return
        bits = cls.target_to_bits(target)
        if bits != header.get('bits'):
            raise Exception("bits mismatch: %s vs %s" % (bits, header.get('bits')))
        block_hash_as_num = int.from_bytes(bfh(_hash), byteorder='big')
        if block_hash_as_num > target:
            raise Exception(f"insufficient proof of work: {block_hash_as_num} vs target {target}")

        # only verify header post equihash fork
        if is_post_equihash_fork(header.get('block_height')):
            header_bytes = bytes.fromhex(serialize_header(header))
            nonce = uint256_from_bytes(bfh(header.get('nonce'))[::-1])
            solution = bfh(header.get('solution'))[::-1]
            offset, length = var_int_read(solution, 0)
            solution = solution[offset:]

            params = get_equihash_params(header.get('block_height'))

            if not is_gbp_valid(header_bytes, nonce, solution, params):
                raise Exception("Invalid equihash solution")

    # verify chunk and return verified headers contained by this chunk
    def verify_chunk(self, index: int, data: bytes) -> list:

        height = idx * constants.net.CHUNK_SIZE
        size = len(data)
        offset = 0
        prev_hash = self.get_hash(height-1)

        headers = {}
        target = 0

        while offset < size:
            try:
                expected_header_hash = self.get_hash(height)
            except MissingHeader:
                expected_header_hash = None

            header_size = get_header_size(height)
            raw_header = data[offset:(offset + header_size)]
            header = deserialize_header(raw_header, height)
            headers[height] = header

            # Check retarget
            if height > constants.net.EQUIHASH_FORK_HEIGHT and (needs_retarget(height) or target == 0):
                target = self.get_target(height, headers)

            self.verify_header(header, prev_hash, target, expected_header_hash)
            prev_hash = hash_header(header, height)
            offset += header_size
            height += 1

        return list(headers.values())

    @with_lock
    def path(self):
        d = util.get_headers_dir(self.config)
        if self.parent is None:
            filename = 'blockchain_headers'
        else:
            assert self.forkpoint > 0, self.forkpoint
            prev_hash = self._prev_hash.lstrip('0')
            first_hash = self._forkpoint_hash.lstrip('0')
            basename = f'fork2_{self.forkpoint}_{prev_hash}_{first_hash}'
            filename = os.path.join('forks', basename)
        return os.path.join(d, filename)

    def save_chunk(self, index: int, headerlist: list) -> None:

        assert index >= 0, index
        assert len(headerlist) == constants.net.CHUNK_SIZE

        chunk_within_checkpoint_region = index < len(self.checkpoints)
        # chunks in checkpoint region are the responsibility of the 'main chain'
        if chunk_within_checkpoint_region and self.parent is not None:
            main_chain = get_best_chain()
            main_chain.save_chunk(index, headerlist)
            return

        self.headerdb.save_header_chunk(headerlist)
        self.swap_with_parent()

    def swap_with_parent(self) -> None:
        with self.lock, blockchains_lock:
            # do the swap; possibly multiple ones
            cnt = 0
            while True:
                old_parent = self.parent
                if not self._swap_with_parent():
                    break
                # make sure we are making progress
                cnt += 1
                if cnt > len(blockchains):
                    raise Exception(f'swapping fork with parent too many times: {cnt}')
                # we might have become the parent of some of our former siblings
                for old_sibling in old_parent.get_direct_children():
                    if self.check_hash(old_sibling.forkpoint - 1, old_sibling._prev_hash):
                        old_sibling.parent = self

    def _swap_with_parent(self) -> bool:
        """Check if this chain became stronger than its parent, and swap
        the underlying files(leveldb file for BTG) if so. The Blockchain instances will keep
        'containing' the same headers, but their ids change and so
        they will be stored in different files(leveldb file for BTG)."""
        if self.parent is None:
            return False
        if self.parent.get_chainwork() >= self.get_chainwork():
            return False
        self.logger.info(f"swapping {self.forkpoint} {self.parent.forkpoint}")
        parent_branch_size = self.parent.height() - self.forkpoint + 1
        forkpoint = self.forkpoint  # type: Optional[int]
        parent = self.parent  # type: Optional[Blockchain]
        child_old_id = self.get_id()
        parent_old_id = parent.get_id()
        # swap files
        # child takes parent's name
        # parent's new name will be something new (not child's old name)
        self.assert_headers_file_available(self.path())
        child_old_name = self.path()
        self.assert_headers_file_available(parent.path())
        # swap parameters
        self._forkpoint_hash, parent._forkpoint_hash = parent._forkpoint_hash, hash_raw_header(serialize_header(self.read_header(self.forkpoint)))
        self.parent, parent.parent = parent.parent, self  # type: Optional[Blockchain], Optional[Blockchain]
        self.forkpoint, parent.forkpoint = parent.forkpoint, self.forkpoint
        self.headerdb, parent.headerdb = parent.headerdb, self.headerdb
        self._prev_hash, parent._prev_hash = parent._prev_hash, self._prev_hash
        # parent's new name
        os.replace(child_old_name, parent.path())
        # update pointers
        blockchains.pop(child_old_id, None)
        blockchains.pop(parent_old_id, None)
        blockchains[self.get_id()] = self
        blockchains[parent.get_id()] = parent
        return True

    def get_id(self) -> str:
        return self._forkpoint_hash

    def assert_headers_file_available(self, path):
        if os.path.exists(path):
            return
        elif not os.path.exists(util.get_headers_dir(self.config)):
            raise FileNotFoundError('Electrum headers_dir does not exist. Was it deleted while running?')
        else:
            raise FileNotFoundError('Cannot find headers file but headers_dir is there. Should be at {}'.format(path))

    @with_lock
    def write(self, data: bytes, offset: int, truncate: bool=True) -> None:
        pass
    
    @with_lock
    def save_header(self, header: dict) -> None:
        height = header.get('block_height')
        # headers are only _appended_ to the end if header is not forkpoint header to saved of the chain:
        if (height != self.forkpoint):
            assert (height == (self._height + 1)), (height, self._height)

        self.headerdb.save_header(header)
        self.logger.info(f'saved header into database at height: {height}')
        self.swap_with_parent()
        if self._height < height:
            self._height = height

    @with_lock
    def read_header(self, height: int) -> Optional[dict]:
        if height < 0:
            return
        if height < self.forkpoint:
            if self.parent is None:
                return
            return self.parent.read_header(height)
        if height > self.height():
            return
        
        return self.headerdb.read_header(height)

    def header_at_tip(self) -> Optional[dict]:
        """Return latest header."""
        height = self.height()
        return self.read_header(height)   
        
    def is_tip_stale(self) -> bool:
        STALE_DELAY = 8 * 60 * 60  # in seconds
        header = self.header_at_tip()
        if not header:
            return True
        # note: We check the timestamp only in the latest header.
        #       The Bitcoin consensus has a lot of leeway here:
        #       - needs to be greater than the median of the timestamps of the past 11 blocks, and
        #       - up to at most 2 hours into the future compared to local clock
        #       so there is ~2 hours of leeway in either direction
        if header['timestamp'] + STALE_DELAY < time.time():
            return True
        return False

    def get_hash(self, height: int) -> str:
        def is_height_checkpoint():
            within_cp_range = height <= constants.net.max_checkpoint()
            at_chunk_boundary = (height+1) % 2016 == 0
            return within_cp_range and at_chunk_boundary

        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return constants.net.GENESIS
        elif is_height_checkpoint():
            index = height // 2016
            h, t = self.checkpoints[index]
            return h
        else:
            header = self.read_header(height)
            if header is None:
                raise MissingHeader(height)
            return hash_header(header)

    def get_header(self, height, headers=None) -> Optional[dict]:
        if headers is None:
            headers = {}

        return headers[height] if height in headers else self.read_header(height)

    def get_target(self, height, headers=None):
        if headers is None:
            headers = {}

        # Check for genesis
        if height == 0:
            new_target = constants.net.POW_LIMIT_LEGACY
        # Check for valid checkpoint
        elif height % difficulty_adjustment_interval() == 0 and 0 <= ((height // difficulty_adjustment_interval()) - 1) < len(self.checkpoints):
            h, t = self.checkpoints[((height // difficulty_adjustment_interval()) - 1)]
            new_target = t
        # Check for prefork
        elif height < constants.net.BTG_HEIGHT:
            new_target = self.get_legacy_target(height, headers)
        # Premine
        elif height < constants.net.BTG_HEIGHT + constants.net.PREMINE_SIZE:
            new_target = constants.net.POW_LIMIT
        # Initial start of BTG Fork (reduced difficulty)
        elif height < constants.net.BTG_HEIGHT + constants.net.PREMINE_SIZE + constants.net.DIGI_AVERAGING_WINDOW:
            new_target = constants.net.POW_LIMIT_START
        # Digishield
        elif height < constants.net.LWMA_HEIGHT:
            new_target = self.get_digishield_target(height, headers)
        # Zawy LWMA (old)
        elif height < constants.net.EQUIHASH_FORK_HEIGHT:
            new_target = self.get_lwma_target(height, headers, constants.net.LWMA_ADJUST_WEIGHT_LEGACY,
                                              constants.net.LWMA_MIN_DENOMINATOR_LEGACY)
        # Initial start of BTG Equihash Fork (reduced difficulty)
        elif height < constants.net.EQUIHASH_FORK_HEIGHT + constants.net.LWMA_AVERAGING_WINDOW:
            last = self.get_header((height - 1), headers)
            bits = last.get('bits')
            new_target = self.bits_to_target(bits)

            if height == constants.net.EQUIHASH_FORK_HEIGHT:
                # reduce diff
                new_target *= 100

                if new_target > constants.net.POW_LIMIT:
                    new_target = constants.net.POW_LIMIT
        # Zawy LWMA (new)
        else:
            new_target = self.get_lwma_target(height, headers, constants.net.LWMA_ADJUST_WEIGHT,
                                              constants.net.LWMA_MIN_DENOMINATOR)

        return new_target

    def get_legacy_target(self, height, headers):
        last_height = (height - 1)
        last = self.get_header(last_height, headers)

        if constants.net == constants.BitcoinGoldRegtest:
            new_target = self.bits_to_target(last.get('bits'))
        elif height % difficulty_adjustment_interval() != 0:
            if constants.net == constants.BitcoinGoldTestnet:
                cur = self.get_header(height, headers)

                # Special testnet handling
                if cur.get('timestamp') > last.get('timestamp') + constants.net.POW_TARGET_SPACING * 2:
                    new_target = constants.net.POW_LIMIT_LEGACY
                else:
                    # Return the last non-special-min-difficulty-rules-block
                    prev_height = last_height - 1
                    prev = self.get_header(prev_height, headers)

                    while prev is not None and last.get('block_height') % difficulty_adjustment_interval() != 0 \
                            and last.get('bits') == constants.net.POW_LIMIT:
                        last = prev
                        prev_height -= 1
                        prev = self.get_header(prev_height, headers)

                    new_target = self.bits_to_target(last.get('bits'))
            else:
                new_target = self.bits_to_target(last.get('bits'))
        else:
            first = self.read_header(height - difficulty_adjustment_interval())
            target = self.bits_to_target(last.get('bits'))

            actual_timespan = last.get('timestamp') - first.get('timestamp')
            target_timespan = constants.net.POW_TARGET_TIMESPAN_LEGACY
            actual_timespan = max(actual_timespan, target_timespan // 4)
            actual_timespan = min(actual_timespan, target_timespan * 4)

            new_target = min(constants.net.POW_LIMIT_LEGACY, (target * actual_timespan) // target_timespan)

        return new_target

    def get_lwma_target(self, height, headers, weight, denominator):
        cur = self.get_header(height, headers)
        last_height = (height - 1)
        last = self.get_header(last_height, headers)

        # Special testnet handling
        if constants.net == constants.BitcoinGoldRegtest:
            new_target = self.bits_to_target(last.get('bits'))
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
                cur = self.get_header(i, headers)
                prev_height = (i - 1)
                prev = self.get_header(prev_height, headers)

                solvetime = cur.get('timestamp') - prev.get('timestamp')

                if constants.net.LWMA_SOLVETIME_LIMITATION and solvetime > ts:
                    solvetime = ts

                j += 1
                t += solvetime * j
                total += self.bits_to_target(cur.get('bits')) // (weight * constants.net.LWMA_AVERAGING_WINDOW * constants.net.LWMA_AVERAGING_WINDOW)

            # Keep t reasonable in case strange solvetimes occurred.
            if t < constants.net.LWMA_AVERAGING_WINDOW * weight // denominator:
                t = constants.net.LWMA_AVERAGING_WINDOW * weight // denominator

            new_target = t * total

            if new_target > constants.net.POW_LIMIT:
                new_target = constants.net.POW_LIMIT

        return new_target

    def get_digishield_target(self, height, headers):
        pow_limit = constants.net.POW_LIMIT
        height -= 1
        last = self.get_header(height, headers)

        if last is None:
            new_target = pow_limit
        elif constants.net.REGTEST:
            new_target = self.bits_to_target(last.get('bits'))
        else:
            first = last
            total = 0
            i = 0

            while i < constants.net.DIGI_AVERAGING_WINDOW and first is not None:
                total += self.bits_to_target(first.get('bits'))
                prev_height = height - i - 1
                first = self.get_header(prev_height, headers)
                i += 1

            # This should never happen else we have a serious problem
            assert first is not None

            avg = total // constants.net.DIGI_AVERAGING_WINDOW
            actual_timespan = self.get_mediantime_past(headers, last.get('block_height')) \
                - self.get_mediantime_past(headers, first.get('block_height'))

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

    def get_mediantime_past(self, headers, start_height):
        header = self.get_header(start_height, headers)

        times = []
        i = 0

        while i < 11 and header is not None:
            times.append(header.get('timestamp'))
            prev_height = start_height - i - 1
            header = self.get_header(prev_height, headers)
            i += 1

        times.sort()
        return times[(len(times) // 2)]

    @classmethod
    def bits_to_target(cls, bits: int) -> int:
        bitsN = (bits >> 24) & 0xff
        if not (0x03 <= bitsN <= 0x1d):
            raise Exception("First part of bits should be in [0x03, 0x1d]")
        bitsBase = bits & 0xffffff
        if not (0x8000 <= bitsBase <= 0x7fffff):
            raise Exception("Second part of bits should be in [0x8000, 0x7fffff]")
        return bitsBase << (8 * (bitsN-3))

    @classmethod
    def target_to_bits(cls, target: int) -> int:
        c = ("%064x" % target)[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) // 2, int.from_bytes(bfh(c[:6]), byteorder='big')
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        return bitsN << 24 | bitsBase

    def chainwork_of_header_at_height(self, height: int) -> int:
        pass

    def get_chainwork(self, height=None) -> int:
        pass

    def can_connect(self, header: dict, check_height: bool=True):
        if header is None:
            return False
        height = header['block_height']
        if check_height and self.height() != height - 1:
            self.logger.error(f'cannot connect at height {height}, because chain height != height - 1')
            return False
        if height == 0:
            return hash_header(header, height) == constants.net.GENESIS
        try:
            prev_hash = self.get_hash(height - 1)
        except:
            return False
        if prev_hash != header.get('prev_block_hash'):
            self.logger.error(f'cannot connect at height {height}, because pre_block_hash check failed')
            return False

        if constants.net == constants.BitcoinGoldRegtest or constants.net == constants.BitcoinGoldTestnet:
            return True

        # do not check targt of headers before equihash fork 
        if height < constants.net.EQUIHASH_FORK_HEIGHT:
            return True
        
        target = self.get_target(height, {height: header})
        try:
            self.verify_header(header, prev_hash, target, None)
        except BaseException as e:
            self.logger.error(f'cannot connect at height {height}, because verify header failed')
            return False
        return True

    def connect_chunk(self, idx: int, hexdata: str) -> bool:
        assert idx >= 0, idx
        try:
            data = bfh(hexdata)
            headerlist = self.verify_chunk(idx, data)
            self.logger.info(f'validated chunk, index: {idx} - verifed header size: {len(headerlist)}')
            self.save_chunk(idx, headerlist)
            return True
        except BaseException as e:
            self.logger.info(f'verify_chunk idx {idx} failed: {repr(e)}')
            return False

    def get_checkpoints(self):
        # for each chunk, store the hash of the last block and the target after the chunk
        cp = []
        n = self.height() // constants.net.CHUNK_SIZE
        for index in range(n):
            height = (index+1) * constants.net.CHUNK_SIZE -1
            headerhash = self.get_hash(height)
            header = self.read_header(height)
            target = self.get_target(height, {height: header})
            cp.append((h, target))
        return cp


def check_header(header: dict) -> Optional[Blockchain]:
    """Returns any Blockchain that contains header, or None."""
    if type(header) is not dict:
        return None
    with blockchains_lock: chains = list(blockchains.values())
    for b in chains:
        if b.check_header(header):
            return b
    return None


def can_connect(header: dict) -> Optional[Blockchain]:
    """Returns the Blockchain that has a tip that directly links up
    with header, or None.
    """
    with blockchains_lock: chains = list(blockchains.values())
    for b in chains:
        if b.can_connect(header):
            return b
    return None


def get_chains_that_contain_header(height: int, header_hash: str) -> Sequence[Blockchain]:
    """Returns a list of Blockchains that contain header, best chain first."""
    with blockchains_lock: chains = list(blockchains.values())
    chains = [chain for chain in chains
              if chain.check_hash(height=height, header_hash=header_hash)]
    chains = sorted(chains, key=lambda x: x.get_chainwork(), reverse=True)
    return chains

