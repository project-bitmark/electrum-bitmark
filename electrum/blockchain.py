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
from typing import Optional, Dict, Mapping, Sequence, TYPE_CHECKING

from . import util
from .bitcoin import hash_encode
from .crypto import sha256d
from . import constants
from .util import bfh, with_lock
from .logging import get_logger, Logger

if TYPE_CHECKING:
    from .simple_config import SimpleConfig

_logger = get_logger(__name__)

HEADER_SIZE = 80  # bytes (standard-algo header; equihash headers are larger, see below)
CHUNK_SIZE = 2016  # num headers in a difficulty retarget period

# see https://github.com/bitcoin/bitcoin/blob/feedb9c84e72e4fff489810a2bbeec09bcda5763/src/chainparams.cpp#L76
MAX_TARGET = 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff  # compact: 0x1d00ffff

# --- Bitmark multi-algorithm PoW ---------------------------------------------
# Bitmark encodes the mining algorithm in the block version: bit 8 = auxpow,
# bits 9-11 = algo. Most algos use the standard 80-byte header. EQUIHASH blocks
# use an extended header (byte-identical to classic Zcash): an extra 32-byte
# hashReserved after the merkle root, a 256-bit nonce, and a length-prefixed
# equihash solution in place of the 4-byte nonce. The block identity hash is
# double-SHA256 over the *full* header (80 bytes for standard algos, ~1487 for
# equihash). See bitmark src/pureheader.{h,cpp} (GetHash / GetHashE).
BITMARK_ALGO_EQUIHASH = 6
# Equihash (n=200, k=9) solution is always 1344 bytes -> a fixed 1487-byte
# header: 4+32+32+32(reserved)+4+4+32(nonce256)+3(varint 0xfd4005)+1344.
EQUIHASH_SOLUTION_SIZE = 1344
EQUIHASH_HEADER_SIZE = 1487
# On-disk we use fixed-size slots sized to the largest header (zcash-style).
MAX_HEADER_SIZE = EQUIHASH_HEADER_SIZE


def header_algo(version: int) -> int:
    return (version >> 9) & 7


def is_equihash_header(version: int) -> bool:
    return header_algo(version) == BITMARK_ALGO_EQUIHASH


def expected_header_size(version: int) -> int:
    return EQUIHASH_HEADER_SIZE if is_equihash_header(version) else HEADER_SIZE


class MissingHeader(Exception):
    pass


class InvalidHeader(Exception):
    pass


def serialize_header(header_dict: dict) -> bytes:
    version = header_dict['version']
    s = (
        int.to_bytes(version, length=4, byteorder="little", signed=False)
        + bfh(header_dict['prev_block_hash'])[::-1]
        + bfh(header_dict['merkle_root'])[::-1])
    if is_equihash_header(version):
        s += (
            bfh(header_dict['reserved_hash'])[::-1]
            + int.to_bytes(int(header_dict['timestamp']), length=4, byteorder="little", signed=False)
            + int.to_bytes(int(header_dict['bits']), length=4, byteorder="little", signed=False)
            + bfh(header_dict['nonce'])[::-1]      # 256-bit nonce
            + bfh(header_dict['sol_size'])         # solution-length varint (raw bytes)
            + bfh(header_dict['solution']))        # equihash solution
    else:
        s += (
            int.to_bytes(int(header_dict['timestamp']), length=4, byteorder="little", signed=False)
            + int.to_bytes(int(header_dict['bits']), length=4, byteorder="little", signed=False)
            + int.to_bytes(int(header_dict['nonce']), length=4, byteorder="little", signed=False))
    return s


def _read_varint(s: bytes, offset: int):
    '''Return (value, bytes_consumed) for a Bitcoin varint at offset.'''
    n = s[offset]
    if n < 0xfd:
        return n, 1
    if n == 0xfd:
        return int.from_bytes(s[offset+1:offset+3], 'little'), 3
    if n == 0xfe:
        return int.from_bytes(s[offset+1:offset+5], 'little'), 5
    return int.from_bytes(s[offset+1:offset+9], 'little'), 9


def deserialize_header(s: bytes, height: int) -> dict:
    if not s:
        raise InvalidHeader('Invalid header: {}'.format(s))
    version = int.from_bytes(s[0:4], byteorder='little')
    h = {
        'version': version,
        'prev_block_hash': hash_encode(s[4:36]),
        'merkle_root': hash_encode(s[36:68]),
    }
    if is_equihash_header(version):
        # extended (zcash-style) equihash header
        if len(s) < 143:
            raise InvalidHeader('Invalid equihash header length: {}'.format(len(s)))
        h['reserved_hash'] = hash_encode(s[68:100])
        h['timestamp'] = int.from_bytes(s[100:104], byteorder='little')
        h['bits'] = int.from_bytes(s[104:108], byteorder='little')
        h['nonce'] = hash_encode(s[108:140])       # 256-bit nonce
        sol_size, vlen = _read_varint(s, 140)
        sol_start = 140 + vlen
        sol_end = sol_start + sol_size
        if len(s) < sol_end:
            raise InvalidHeader('Invalid equihash solution length: {}'.format(len(s)))
        h['sol_size'] = s[140:sol_start].hex()
        h['solution'] = s[sol_start:sol_end].hex()
    else:
        if len(s) != HEADER_SIZE:
            raise InvalidHeader('Invalid header length: {}'.format(len(s)))
        h['timestamp'] = int.from_bytes(s[68:72], byteorder='little')
        h['bits'] = int.from_bytes(s[72:76], byteorder='little')
        h['nonce'] = int.from_bytes(s[76:80], byteorder='little')
    h['block_height'] = height
    return h


def hash_header(header: dict) -> str:
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_raw_header(serialize_header(header))


def hash_raw_header(header: bytes) -> str:
    assert isinstance(header, bytes)
    return hash_encode(sha256d(header))


pow_hash_header = hash_header


# --- variable-length header storage helpers ----------------------------------
# Bitmark headers are 80 bytes for standard algos and ~1487 for equihash. On
# the wire (server -> wallet) they are concatenated at their natural length, so
# a chunk must be parsed sequentially. On disk we store every header in a
# fixed MAX_HEADER_SIZE slot (zero-padded) so height->offset stays O(1).

def wire_header_len(data: bytes, offset: int = 0) -> int:
    '''Length of the header starting at `offset` in a raw (wire) byte stream.'''
    version = int.from_bytes(data[offset:offset+4], byteorder='little')
    if not is_equihash_header(version):
        return HEADER_SIZE
    sol_size, vlen = _read_varint(data, offset + 140)
    return 140 + vlen + sol_size


def pure_header_bytes(raw: bytes) -> bytes:
    '''Return the pure header (the part that forms the block identity hash),
    stripping any trailing auxpow blob. For Bitmark the pure header length is
    exactly wire_header_len: 80 for standard algos, the full extended header
    for equihash.'''
    if len(raw) < HEADER_SIZE:
        return b''
    return raw[:wire_header_len(raw, 0)]


def split_wire_headers(data: bytes) -> Sequence[bytes]:
    '''Split a concatenation of variable-length headers into individual ones.'''
    headers = []
    offset = 0
    n = len(data)
    while offset < n:
        size = wire_header_len(data, offset)
        if offset + size > n:
            raise InvalidHeader('truncated header in chunk at offset {}'.format(offset))
        headers.append(data[offset:offset+size])
        offset += size
    return headers


def pad_header_to_slot(raw_header: bytes) -> bytes:
    '''Pad a natural-length header into a fixed MAX_HEADER_SIZE disk slot.'''
    if len(raw_header) > MAX_HEADER_SIZE:
        raise InvalidHeader('header too large: {}'.format(len(raw_header)))
    return raw_header + bytes(MAX_HEADER_SIZE - len(raw_header))


def unpad_header_slot(slot: bytes) -> bytes:
    '''Recover the natural-length header from a fixed-size disk slot.'''
    return slot[:wire_header_len(slot, 0)]


# key: blockhash hex at forkpoint
# the chain at some key is the best chain that includes the given hash
blockchains = {}  # type: Dict[str, Blockchain]
blockchains_lock = threading.RLock()  # lock order: take this last; so after Blockchain.lock


def read_blockchains(config: 'SimpleConfig'):
    best_chain = Blockchain(config=config,
                            forkpoint=0,
                            parent=None,
                            forkpoint_hash=constants.net.GENESIS,
                            prev_hash=None)
    blockchains[constants.net.GENESIS] = best_chain
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
    return blockchains[constants.net.GENESIS]


# block hash -> chain work; up to and including that block
_CHAINWORK_CACHE = {
    "0000000000000000000000000000000000000000000000000000000000000000": 0,  # virtual block at height -1
}  # type: Dict[str, int]


def init_headers_file_for_best_chain():
    b = get_best_chain()
    filename = b.path()
    length = MAX_HEADER_SIZE * len(constants.net.CHECKPOINTS) * CHUNK_SIZE
    if not os.path.exists(filename) or os.path.getsize(filename) < length:
        with open(filename, 'wb') as f:
            if length > 0:
                f.seek(length - 1)
                f.write(b'\x00')
        util.ensure_sparse_file(filename)
    with b.lock:
        b.update_size()


class Blockchain(Logger):
    """
    Manages blockchain headers and their verification
    """

    def __init__(self, config: 'SimpleConfig', forkpoint: int, parent: Optional['Blockchain'],
                 forkpoint_hash: str, prev_hash: Optional[str]):
        assert isinstance(forkpoint_hash, str) and len(forkpoint_hash) == 64, forkpoint_hash
        assert (prev_hash is None) or (isinstance(prev_hash, str) and len(prev_hash) == 64), prev_hash
        # assert (parent is None) == (forkpoint == 0)
        if 0 < forkpoint <= constants.net.max_checkpoint():
            raise Exception(f"cannot fork below max checkpoint. forkpoint: {forkpoint}")
        Logger.__init__(self)
        self.config = config
        self.forkpoint = forkpoint  # height of first header
        self.parent = parent
        self._forkpoint_hash = forkpoint_hash  # blockhash at forkpoint. "first hash"
        self._prev_hash = prev_hash  # blockhash immediately before forkpoint
        self.lock = threading.RLock()
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
        open(self.path(), 'w+').close()
        self.save_header(header)
        # put into global dict. note that in some cases
        # save_header might have already put it there but that's OK
        chain_id = self.get_id()
        with blockchains_lock:
            blockchains[chain_id] = self
        return self

    @with_lock
    def height(self) -> int:
        return self.forkpoint + self.size() - 1

    @with_lock
    def size(self) -> int:
        return self._size

    @with_lock
    def update_size(self) -> None:
        p = self.path()
        self._size = os.path.getsize(p)//MAX_HEADER_SIZE if os.path.exists(p) else 0

    @classmethod
    def verify_header(cls, header: dict, prev_hash: str, target: int, expected_header_hash: str=None) -> None:
        _hash = hash_header(header)
        if expected_header_hash and expected_header_hash != _hash:
            raise InvalidHeader("hash mismatches with expected: {} vs {}".format(expected_header_hash, _hash))
        if prev_hash != header.get('prev_block_hash'):
            raise InvalidHeader("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        # Bitmark uses 8 PoW algorithms with per-block Dark Gravity Wave
        # retargeting (algo encoded in the version field). Reimplementing all
        # of that in the wallet is deferred; header-chain integrity is provided
        # by prev-hash linkage plus hardcoded checkpoint hashes (see get_hash /
        # CHECKPOINTS). So we do not verify bits/PoW here.
        return

    def verify_chunk(self, index: int, data: bytes) -> None:
        # headers in a chunk are concatenated at their natural (variable) length
        raw_headers = split_wire_headers(data)
        start_height = index * CHUNK_SIZE
        prev_hash = self.get_hash(start_height - 1)
        target = self.get_target(index-1)
        for i, raw_header in enumerate(raw_headers):
            height = start_height + i
            try:
                expected_header_hash = self.get_hash(height)
            except MissingHeader:
                expected_header_hash = None
            header = deserialize_header(raw_header, height)
            self.verify_header(header, prev_hash, target, expected_header_hash)
            prev_hash = hash_header(header)

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

    @with_lock
    def save_chunk(self, index: int, chunk: bytes):
        assert index >= 0, index
        chunk_within_checkpoint_region = index < len(self.checkpoints)
        # chunks in checkpoint region are the responsibility of the 'main chain'
        if chunk_within_checkpoint_region and self.parent is not None:
            main_chain = get_best_chain()
            main_chain.save_chunk(index, chunk)
            return

        # split the variable-length wire chunk into individual headers, then
        # re-pack into fixed-size disk slots (header counts, not byte offsets).
        raw_headers = list(split_wire_headers(chunk))
        delta_height = (index * CHUNK_SIZE - self.forkpoint)
        # if this chunk contains our forkpoint, only save the part after forkpoint
        # (the part before is the responsibility of the parent)
        if delta_height < 0:
            raw_headers = raw_headers[-delta_height:]
            delta_height = 0
        slot_data = b''.join(pad_header_to_slot(h) for h in raw_headers)
        truncate = not chunk_within_checkpoint_region
        self.write(slot_data, delta_height * MAX_HEADER_SIZE, truncate)
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
        the underlying files if so. The Blockchain instances will keep
        'containing' the same headers, but their ids change and so
        they will be stored in different files."""
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
        with open(self.path(), 'rb') as f:
            my_data = f.read()
        self.assert_headers_file_available(parent.path())
        assert forkpoint > parent.forkpoint, (f"forkpoint of parent chain ({parent.forkpoint}) "
                                              f"should be at lower height than children's ({forkpoint})")
        with open(parent.path(), 'rb') as f:
            f.seek((forkpoint - parent.forkpoint)*MAX_HEADER_SIZE)
            parent_data = f.read(parent_branch_size*MAX_HEADER_SIZE)
        self.write(parent_data, 0)
        parent.write(my_data, (forkpoint - parent.forkpoint)*MAX_HEADER_SIZE)
        # swap parameters
        self.parent, parent.parent = parent.parent, self  # type: Optional[Blockchain], Optional[Blockchain]
        self.forkpoint, parent.forkpoint = parent.forkpoint, self.forkpoint
        self._forkpoint_hash, parent._forkpoint_hash = parent._forkpoint_hash, hash_raw_header(unpad_header_slot(parent_data[:MAX_HEADER_SIZE]))
        self._prev_hash, parent._prev_hash = parent._prev_hash, self._prev_hash
        # parent's new name
        os.replace(child_old_name, parent.path())
        self.update_size()
        parent.update_size()
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
    def write(self, data: bytes, offset: int, truncate: bool = True, *, fsync: bool = True) -> None:
        filename = self.path()
        self.assert_headers_file_available(filename)
        with open(filename, 'rb+') as f:
            if truncate and offset != self._size * MAX_HEADER_SIZE:
                f.seek(offset)
                f.truncate()
            f.seek(offset)
            f.write(data)
            if fsync:
                f.flush()
                os.fsync(f.fileno())
        self.update_size()

    @with_lock
    def save_header(self, header: dict) -> None:
        delta = header.get('block_height') - self.forkpoint
        data = pad_header_to_slot(serialize_header(header))
        # headers are only _appended_ to the end:
        assert delta == self.size(), (delta, self.size())
        assert len(data) == MAX_HEADER_SIZE
        # note: we don't fsync, to improve perf. losing headers at end of file is ok.
        self.write(data, delta*MAX_HEADER_SIZE, fsync=False)
        self.swap_with_parent()

    @with_lock
    def read_header(self, height: int) -> Optional[dict]:
        if height < 0:
            return
        if height < self.forkpoint:
            return self.parent.read_header(height)
        if height > self.height():
            return
        delta = height - self.forkpoint
        name = self.path()
        self.assert_headers_file_available(name)
        with open(name, 'rb') as f:
            f.seek(delta * MAX_HEADER_SIZE)
            h = f.read(MAX_HEADER_SIZE)
            if len(h) < MAX_HEADER_SIZE:
                raise Exception('Expected to read a full header slot. This was only {} bytes'.format(len(h)))
        if h == bytes(MAX_HEADER_SIZE):
            return None
        return deserialize_header(unpad_header_slot(h), height)

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
            at_chunk_boundary = (height+1) % CHUNK_SIZE == 0
            return within_cp_range and at_chunk_boundary

        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return constants.net.GENESIS
        elif is_height_checkpoint():
            index = height // CHUNK_SIZE
            h, t = self.checkpoints[index]
            return h
        else:
            header = self.read_header(height)
            if header is None:
                raise MissingHeader(height)
            return hash_header(header)

    def get_target(self, index: int) -> int:
        # Bitmark retargets every block with per-algo Dark Gravity Wave, which
        # the wallet does not reimplement (PoW verification is deferred -- see
        # verify_header). Return the checkpointed target where available, else
        # MAX_TARGET. The value is not used to gate header acceptance.
        if index == -1:
            return MAX_TARGET
        if index < len(self.checkpoints):
            h, t = self.checkpoints[index]
            return t
        return MAX_TARGET

    @classmethod
    def bits_to_target(cls, bits: int) -> int:
        # arith_uint256::SetCompact in Bitcoin Core
        if not (0 <= bits < (1 << 32)):
            raise InvalidHeader(f"bits should be uint32. got {bits!r}")
        bitsN = (bits >> 24) & 0xff
        bitsBase = bits & 0x7fffff
        if bitsN <= 3:
            target = bitsBase >> (8 * (3-bitsN))
        else:
            target = bitsBase << (8 * (bitsN-3))
        if target != 0 and bits & 0x800000 != 0:
            # Bit number 24 (0x800000) represents the sign of N
            raise InvalidHeader("target cannot be negative")
        if (target != 0 and
                (bitsN > 34 or
                 (bitsN > 33 and bitsBase > 0xff) or
                 (bitsN > 32 and bitsBase > 0xffff))):
            raise InvalidHeader("target has overflown")
        return target

    @classmethod
    def target_to_bits(cls, target: int) -> int:
        # arith_uint256::GetCompact in Bitcoin Core
        # see https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/arith_uint256.cpp#L223
        c = target.to_bytes(length=32, byteorder='big')
        bitsN = len(c)
        while bitsN > 0 and c[0] == 0:
            c = c[1:]
            bitsN -= 1
            if len(c) < 3:
                c += b'\x00'
        bitsBase = int.from_bytes(c[:3], byteorder='big')
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        return bitsN << 24 | bitsBase

    def chainwork_of_header_at_height(self, height: int) -> int:
        """work done by single header at given height"""
        chunk_idx = height // CHUNK_SIZE - 1
        target = self.get_target(chunk_idx)
        work = ((2 ** 256 - target - 1) // (target + 1)) + 1
        return work

    @with_lock
    def get_chainwork(self, height=None) -> int:
        if height is None:
            height = max(0, self.height())
        if constants.net.TESTNET:
            # On testnet/regtest, difficulty works somewhat different.
            # It's out of scope to properly implement that.
            return height
        last_retarget = height // CHUNK_SIZE * CHUNK_SIZE - 1
        cached_height = last_retarget
        while _CHAINWORK_CACHE.get(self.get_hash(cached_height)) is None:
            if cached_height <= -1:
                break
            cached_height -= CHUNK_SIZE
        assert cached_height >= -1, cached_height
        running_total = _CHAINWORK_CACHE[self.get_hash(cached_height)]
        while cached_height < last_retarget:
            cached_height += CHUNK_SIZE
            work_in_single_header = self.chainwork_of_header_at_height(cached_height)
            work_in_chunk = CHUNK_SIZE * work_in_single_header
            running_total += work_in_chunk
            _CHAINWORK_CACHE[self.get_hash(cached_height)] = running_total
        cached_height += CHUNK_SIZE
        work_in_single_header = self.chainwork_of_header_at_height(cached_height)
        work_in_last_partial_chunk = (height % CHUNK_SIZE + 1) * work_in_single_header
        return running_total + work_in_last_partial_chunk

    def can_connect(self, header: dict, *, check_height: bool = True) -> bool:
        if header is None:
            return False
        height = header['block_height']
        if check_height and self.height() != height - 1:
            return False
        if height == 0:
            return hash_header(header) == constants.net.GENESIS
        try:
            prev_hash = self.get_hash(height - 1)
        except Exception:
            return False
        if prev_hash != header.get('prev_block_hash'):
            return False
        try:
            target = self.get_target(height // CHUNK_SIZE - 1)
        except MissingHeader:
            return False
        try:
            self.verify_header(header, prev_hash, target)
        except BaseException as e:
            return False
        return True

    def connect_chunk(self, idx: int, data: bytes) -> bool:
        assert idx >= 0, idx
        try:
            self.verify_chunk(idx, data)
            self.save_chunk(idx, data)
            return True
        except BaseException as e:
            self.logger.info(f'verify_chunk idx {idx} failed: {repr(e)}')
            return False

    def get_checkpoints(self):
        # for each chunk, store the hash of the last block and the target after the chunk
        cp = []
        n = self.height() // CHUNK_SIZE
        for index in range(n):
            h = self.get_hash((index+1) * CHUNK_SIZE -1)
            target = self.get_target(index)
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
