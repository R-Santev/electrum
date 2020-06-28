# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum developers
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
import json

from .util import inv_dict
from . import bitcoin

from .equihash_params import EquihashParams


def read_json(filename, default):
    path = os.path.join(os.path.dirname(__file__), filename)
    try:
        with open(path, 'r') as f:
            r = json.loads(f.read())
    except:
        r = default
    return r


GIT_REPO_URL = "https://github.com/BTCGPU/electrum"
GIT_ISSUE_URL = GIT_REPO_URL + "/issues"


class AbstractNet:

    BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS = 0

    POW_TARGET_SPACING = 10 * 60
    POW_TARGET_TIMESPAN_LEGACY = 14 * 24 * 60 * 60

    DIGI_AVERAGING_WINDOW = 30
    DIGI_MAX_ADJUST_DOWN = 32
    DIGI_MAX_ADJUST_UP = 16

    LWMA_AVERAGING_WINDOW = 45
    LWMA_ADJUST_WEIGHT_LEGACY = 13772
    LWMA_ADJUST_WEIGHT = 13772
    LWMA_MIN_DENOMINATOR_LEGACY = 10
    LWMA_MIN_DENOMINATOR = 10
    LWMA_SOLVETIME_LIMITATION = True

    EQUIHASH_PARAMS = EquihashParams(n=200, k=9, personalization=b'ZcashPoW')
    EQUIHASH_PARAMS_FORK = EquihashParams(n=144, k=5, personalization=b'BgoldPoW')

    HEADER_SIZE_ORIGIN = 80
    HEADER_SIZE_LEGACY = 141
    
    CHUNK_SIZE = 252

    SIGHASH_FORK_BTG = 0x4f40

    @classmethod
    def max_checkpoint(cls) -> int:
        return max(0, len(cls.CHECKPOINTS) * 2016 - 1)

    @classmethod
    def get_checkpoint_hash(cls, height) -> str:
        def is_height_checkpoint():
            within_cp_range = height <= cls.max_checkpoint()
            at_chunk_boundary = (height+1) % 2016 == 0
            return within_cp_range and at_chunk_boundary

        if is_height_checkpoint():
            index = height // 2016
            h, t = cls.CHECKPOINTS[index]
            return h

    @classmethod
    def rev_genesis_bytes(cls) -> bytes:
        return bytes.fromhex(bitcoin.rev_hex(cls.GENESIS))

class BitcoinGoldMainnet(AbstractNet):
    TESTNET = False
    WIF_PREFIX = 0x80
    ADDRTYPE_P2PKH = 38
    ADDRTYPE_P2SH = 23
    SEGWIT_HRP = "btg"
    HEADERS_URL = "https://headers.bitcoingold.org/blockchain_headers.gz"
    GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    DEFAULT_SERVERS = read_json('servers.json', {})
    CHECKPOINTS = read_json('checkpoints.json', [])

    PREMINE_SIZE = 8000
    BTG_HEIGHT = 491407

    LWMA_HEIGHT = 536200

    EQUIHASH_FORK_HEIGHT = 536200

    POW_LIMIT = 0x0007ffffffff0000000000000000000000000000000000000000000000000000
    POW_LIMIT_START = 0x0000000fffff0000000000000000000000000000000000000000000000000000
    POW_LIMIT_LEGACY = 0x00000000ffff0000000000000000000000000000000000000000000000000000

    XPRV_HEADERS = {
        'standard':     0x0488ade4,  # xprv
        'p2wpkh-p2sh':  0x049d7878,  # yprv
        'p2wsh-p2sh':   0x0295b005,  # Yprv
        'p2wpkh':       0x04b2430c,  # zprv
        'p2wsh':        0x02aa7a99,  # Zprv
    }
    XPRV_HEADERS_INV = inv_dict(XPRV_HEADERS)

    XPUB_HEADERS = {
        'standard':     0x0488b21e,  # xpub
        'p2wpkh-p2sh':  0x049d7cb2,  # ypub
        'p2wsh-p2sh':   0x0295b43f,  # Ypub
        'p2wpkh':       0x04b24746,  # zpub
        'p2wsh':        0x02aa7ed3,  # Zpub
    }
    XPUB_HEADERS_INV = inv_dict(XPUB_HEADERS)
    BIP44_COIN_TYPE = 156
    LN_REALM_BYTE = 0
    LN_DNS_SEEDS = [
        'nodes.lightning.directory.',
        'lseed.bitcoinstats.com.',
    ]

    MAX_CHECKPOINT_HEADER = {
        'version': 536870912,
        'prev_block_hash': '0000000754e41450d904adea2910d4fe4491afbc47f5ef25acb31e38dd5a95ab',
        'merkle_root': 'b84d183572ede51e2c2fd1ff0881156f35a760928bb1a3054abac9c8726e37e7',
        'block_height': 637055,
        'reserved': '00000000000000000000000000000000000000000000000000000000',
        'timestamp': 1591480549,
        'bits': 0x1d086483,
        'nonce': '0003089300000003000000000000000000000000000000009de9020000000001',
        'solution':'01e3dbdbfddf61dcf23b751140bb4ef0bcf34c46e3fe532ec8242148c93b4359776a72504d82e40dc74d7bf965f7b78dcabb044209183b57f37819bfd7fe52080c442843eb1387c3b8be9a0826e4b521d147514ba916060296bb958b0fbea2b2bdbea46a'
    }

class BitcoinGoldTestnet(AbstractNet):
    TESTNET = True
    WIF_PREFIX = 0xef
    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    SEGWIT_HRP = "tbtg"
    GENESIS = "00000000e0781ebe24b91eedc293adfea2f557b53ec379e78959de3853e6f9f6"
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    DEFAULT_SERVERS = read_json('servers_testnet.json', {})
    CHECKPOINTS = read_json('checkpoints_testnet.json', [])

    PREMINE_SIZE = 50
    BTG_HEIGHT = 1

    LWMA_HEIGHT = -1
    LWMA_ADJUST_WEIGHT_LEGACY = 13632
    LWMA_ADJUST_WEIGHT = 13772
    LWMA_MIN_DENOMINATOR_LEGACY = 3
    LWMA_MIN_DENOMINATOR = 10
    LWMA_SOLVETIME_LIMITATION = False

    EQUIHASH_FORK_HEIGHT = 14300

    POW_LIMIT = 0x0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    POW_LIMIT_START = 0x0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    POW_LIMIT_LEGACY = 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff

    XPRV_HEADERS = {
        'standard': 0x04358394,     # tprv
        'p2wpkh-p2sh': 0x044a4e28,  # uprv
        'p2wsh-p2sh': 0x024285b5,   # Uprv
        'p2wpkh': 0x045f18bc,       # vprv
        'p2wsh': 0x02575048,        # Vprv
    }
    XPRV_HEADERS_INV = inv_dict(XPRV_HEADERS)

    XPUB_HEADERS = {
        'standard': 0x043587cf,     # tpub
        'p2wpkh-p2sh': 0x044a5262,  # upub
        'p2wsh-p2sh': 0x024289ef,   # Upub
        'p2wpkh': 0x045f1cf6,       # vpub
        'p2wsh': 0x02575483,        # Vpub
    }
    XPUB_HEADERS_INV = inv_dict(XPUB_HEADERS)

    BIP44_COIN_TYPE = 1
    LN_REALM_BYTE = 1
    LN_DNS_SEEDS = [  # TODO investigate this again
        #'test.nodes.lightning.directory.',  # times out.
        #'lseed.bitcoinstats.com.',  # ignores REALM byte and returns mainnet peers...
    ]

    MAX_CHECKPOINT_HEADER = {
        'version': 536870912,
        'prev_block_hash': '00078c55b0972a70d6920cab734c9043d7916fd82dfe7e832455662ff3334c7a',
        'merkle_root': '8a45ebd0c4895c35b98cae7a6ed950c99301e3995283e36fb1f9a8d8f4cce51a',
        'block_height': 78623,
        'reserved': '00000000000000000000000000000000000000000000000000000000',
        'timestamp': 1591897081,
        'bits': 0x1f07ffff,
        'nonce': '0000052d0000000000000000000000000000000000000000000000000004198f',
        'solution':'0d628f363b74106f99d1d867840980ab9b54f6f0ed53f8a1c35d5a2c36ed4f3924137fd914e8d21ed7d64656f3cb1dd553f715af4ac5a883466c1f4e62fce7ca33d744d8539e48f3d2dfdb2d290e4254260edcc7c843ac433354b1d14ce9687683225dac'
    }

class BitcoinGoldRegtest(AbstractNet):
    REGTEST = True

    WIF_PREFIX = 0xef
    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    SEGWIT_HRP = "tbtg"

    GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"

    DEFAULT_SERVERS = read_json('servers_regtest.json', {})

    PREMINE_SIZE = 10
    BTG_HEIGHT = 2000

    LWMA_HEIGHT = -1

    EQUIHASH_FORK_HEIGHT = 2001
    EQUIHASH_PARAMS = EquihashParams(n=48, k=5, personalization=b'ZcashPoW')
    EQUIHASH_PARAMS_FORK = EquihashParams(n=96, k=5, personalization=b'BgoldPoW')

    POW_LIMIT = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    POW_LIMIT_START = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    POW_LIMIT_LEGACY = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

    XPRV_HEADERS = {
        'standard': 0x04358394,     # tprv
        'p2wpkh-p2sh': 0x044a4e28,  # uprv
        'p2wsh-p2sh': 0x024285b5,   # Uprv
        'p2wpkh': 0x045f18bc,       # vprv
        'p2wsh': 0x02575048,        # Vprv
    }

    XPUB_HEADERS = {
        'standard': 0x043587cf,     # tpub
        'p2wpkh-p2sh': 0x044a5262,  # upub
        'p2wsh-p2sh': 0x024289ef,   # Upub
        'p2wpkh': 0x045f1cf6,       # vpub
        'p2wsh': 0x02575483,        # Vpub
    }

    MAX_CHECKPOINT_HEADER = None

# don't import net directly, import the module instead (so that net is singleton)
net = BitcoinGoldMainnet

def set_simnet():
    global net
    net = BitcoinGoldTestnet    # TODO: Add BitcoinGold simnet

def set_mainnet():
    global net
    net = BitcoinGoldMainnet

def set_testnet():
    global net
    net = BitcoinGoldTestnet

def set_regtest():
    global net
    net = BitcoinGoldRegtest
