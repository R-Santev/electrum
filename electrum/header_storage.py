#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2020 The Bitcoin Gold developers
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
from enum import IntEnum
from typing import Optional
import diskcache

from .logging import Logger
from . import blockchain
from .util import profiler, to_bytes, to_string, bfh, standardize_path
from .bitcoin import int_to_hex, rev_hex

def Singleton(cls):
    _instance = {}

    def _singleton(*args, **kargs):
        if cls not in _instance:
            _instance[cls] = cls(*args, **kargs)
        return _instance[cls]

    return _singleton

class HeaderStorageNotContinuousError(Exception): pass


# use shelve to save header
# key: bytes of header height string
# value: bytes of serialized header hex string
# @Singleton
class HeaderStorage(Logger):

    def __init__(self, path):
        Logger.__init__(self)
        self.path = standardize_path(path)
        self._file_exists = bool(self.path and os.path.exists(self.path))
        self.logger.info(f"header path {self.path}")
        self.db = diskcache.Cache(self.path)

    def _header_exist(self, height: int) -> bool:
        try:
            headerstr = self.db.get(str(height))

            if headerstr is None:
                return False
            return True
        except KeyError:
            return False

    def save_header(self, header: dict) -> None:
        if self._header_exist(header['block_height']):
            self.logger.warning(f"block at height {header['block_height']} already exist, will be ignored")
            return

        self.db[str(header['block_height'])] = blockchain.serialize_header(header)

        if header['block_height'] > self.get_latest():
            self.set_latest(header['block_height'])
            self.logger.info(f"latest height of header storage update to {header['block_height']}")

    def read_header(self, height: int) -> Optional[dict]:
        try:
            headerstr = self.db.get(str(height))
            if headerstr is None:
                return None
            return blockchain.deserialize_header(bfh(headerstr), height)
        except KeyError:
            self.logger.warning(f"block at height {height} doesn't exist")
            return None

    def delete_header(self, height: int) -> None:
        del self.db[str(height)]

    # header mast be continuous
    def save_header_chunk(self, headerlist: list) -> None:
        if len(headerlist) == 0:
            return None
        
        last_height = headerlist[0]['block_height']
        for header in headerlist[1:]:
            if(header['block_height'] - last_height == 1):
                last_height = header['block_height']
            else:
                raise HeaderStorageNotContinuousError('header is not continuous during save chunk header')
                
        for header in headerlist:
            self.db[str(header['block_height'])] = blockchain.serialize_header(header)

        self.logger.info(f"{len(headerlist)} blocks saved into header storage")

        if headerlist[-1]['block_height'] > self.get_latest():
            self.set_latest(headerlist[-1]['block_height'])
            self.logger.info(f"latest height of header storage update to {headerlist[-1]['block_height']}")
    
    # height mast be continuous
    def read_header_chunk(self, heightlist: list) -> Optional[list]:
        if len(heightlist) == 0:
            return None
        
        last_height = heightlist[0]
        for height in heightlist[1:]:
            if(height - last_height == 1):
                last_height = height
            else:
                raise HeaderStorageNotContinuousError('height is not continuous during read chunk header')
 
        headerlist = []
        for height in heightlist:
            try:
                headerstr = self.db.get(str(height))
                if headerstr is None:
                    return None
                headerlist.append(blockchain.deserialize_header(bfh(headerstr), height))
            except KeyError:
                self.logger.warning(f"block at height {height} doesn't exist")
                return None

        return headerlist

    # height mast be continuous
    def delete_header_chunk(self, heightlist: list) -> None:
        if len(heightlist) == 0:
            return None
        
        last_height = heightlist[0]
        for height in heightlist[1:]:
            if(height - last_height == 1):
                last_height = height
            else:
                raise HeaderStorageNotContinuousError('height is not continuous during read chunk header')
     
        for height in heightlist:
            del self.db[str(height)]

    def set_latest(self, height: int):
        self.db['latest'] = str(height)

    def get_latest(self) -> int:
        try:
            heightstr = self.db.get('latest')
            if heightstr is None:
                return 0
            return int(heightstr)
        except KeyError:
            return 0


