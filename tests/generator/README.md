# Vector generation

`vectors.py` writes four binary case files to one output folder, which must be outside this repo. It checks the SHA-256 pin of every file it downloads.

```bash
tests/generator/run.sh ~/.cache/asm-quic/vectors
```

`run.sh` runs `vectors.py` in the image of [platform/linux/Dockerfile](../../platform/linux/Dockerfile), with a Python environment in the output folder. It keeps the downloads in `sources/` and the environment in `.venv/`, so a second run downloads nothing again.

| File | Cases | Expected results |
|---|---|---|
| `rfc9001.bin` | RFC 9001 appendix A.1 to A.4: the Initial keys, the client Initial and the server Initial (seal and open), and the Retry tag | The official values of the appendix |
| `packet-generated.bin` | Initial keys of every ID length; seal and open of long and short headers with every packet number length and payload sizes up to the limits; flipped bits, wrong keys, short packets; the example of RFC 9000 appendix A.3; Retry tags | `cryptography` and the steps of RFC 9001 section 5 written out in `vectors.py`, which first reproduce appendix A |
| `libp2p-tls.bin` | The 4 certificates of the libp2p TLS spec | Their peer IDs in the spec must match the host keys the checks give |
| `cert-generated.bin` | Certificates made with `cryptography`: valid ones; the edges of the validity period; critical and unknown extensions; host keys of each type, malformed host keys and wrong host signatures; a secp256k1 signature with a high s; bad self signatures, trailing and missing bytes, P-384 and RSA keys, a missing extension; flipped bits | The checks of the spec written out in `vectors.py` (`ref_cert`) |

| Reference | Pin |
|---|---|
| RFC 9001 | `rfc9001.txt`, by SHA-256 in `vectors.py` |
| libp2p TLS spec | `tls/tls.md` at libp2p/specs `c750236`, by SHA-256 in `vectors.py` |
| `cryptography` | 50.0.2, with `cffi` 2.1.1 and `pycparser` 3.12, by hash in [requirements.txt](requirements.txt) |

## File format

- All numbers are u64, little endian.
- A blob is a u64 length, then its bytes.
- A file is the 8 bytes `QUICVEC1`, a u64 case count, then the cases.
- A case is a u64 kind, a blob name, then the fields of its kind.

| Kind | Function | Fields |
|---|---|---|
| 1 | `quic_initial_keys` | blob dcid, u64 status, 96 bytes InitialKeys |
| 2 | `quic_packet_seal` | 48 bytes PacketKeys, u64 packet number, blob header, blob payload, u64 status, blob sealed packet |
| 3 | `quic_packet_open` | 48 bytes PacketKeys, u64 packet number offset, u64 largest, blob packet, u64 status, u64 packet number, blob header, blob payload |
| 4 | `quic_retry_tag` | blob odcid, blob Retry packet without its tag, u64 status, 16 bytes tag |
| 5 | `quic_cert_verify` | blob certificate, u64 Unix time, u64 status, u64 key kind, blob key, blob host key |
