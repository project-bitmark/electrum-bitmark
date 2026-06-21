# Electrum-Bitmark - Lightweight Bitmark wallet

```
Licence: MIT Licence
Language: Python (>= 3.10)
```

Electrum-Bitmark is a lightweight wallet for [Bitmark](https://github.com/project-bitmark/bitmark)
(ticker **BTMK**). It is a fork of [Electrum](https://github.com/spesmilo/electrum) 4.7.2,
adapted for Bitmark's chain. It talks to an
[electrumx-bitmark](https://github.com/project-bitmark/electrumx-bitmark) server rather than
to a full node directly, so it stays light and fast.

## What's different from upstream Electrum

Bitmark is a 2014-era multi-algorithm chain, which required real changes beyond
re-branding:

- **8 PoW algorithms** (scrypt, sha256d, yescrypt, argon2, x17, lyra2rev2, equihash,
  cryptonight) with the algorithm encoded in the block version. Header
  parsing/serialization/hashing is algo-aware (`electrum/blockchain.py`).
- **Variable-length headers.** Most blocks use the standard 80-byte header; equihash blocks
  use a Zcash-style ~1487-byte extended header (hashed in full, "GetHashE"). Header storage
  and chunk download handle the mixed sizes.
- **AuxPoW (merged mining).** The auxpow blob is stripped from served headers (it is not part
  of the block identity hash).
- **No SegWit / Taproot.** Wallets default to legacy **P2PKH** addresses (start with `b`).
- **Per-algo Dark Gravity Wave difficulty** is not reimplemented in the wallet; header-chain
  integrity comes from prev-hash linkage plus hardcoded checkpoints.
- **BTMK** base units and Electrum-Bitmark branding.

Network parameters (from the Bitmark daemon's `chainparams.cpp`): P2PKH `0x55`, P2SH `0x05`,
WIF `0xd5`, genesis `c1fb746e…79137cb`.

## Quick start (from source)

```bash
python3 -m venv venv && source venv/bin/activate
pip install -e .
pip install cryptography pycryptodomex   # binary deps
# GUI also needs: pip install PyQt6 qdarkstyle

# point at an electrumx-bitmark server and run
./run_electrum --offline setconfig server "<host>:50001:t"
./run_electrum                # GUI
# or headless:
./run_electrum daemon -d && ./run_electrum load_wallet && ./run_electrum getinfo
```

Create a wallet with `./run_electrum create` — it defaults to a legacy seed, so you get
`b…` addresses automatically.

## Status

Stage 2: connects to a local/trusted ElectrumX server, verifies the full header chain across
all algorithms, generates legacy addresses, and queries balances/history. Public-server
infrastructure (Stage 3) is future work.

## Credits

Built on [Electrum](https://github.com/spesmilo/electrum) by Thomas Voegtlin and contributors.
See `LICENCE` and the upstream project for the base wallet documentation.
