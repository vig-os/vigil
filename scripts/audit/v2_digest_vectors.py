"""Independent ADR-0005 V2 digest vectors; uses b3sum, not vigil's implementation.

Run with b3sum on PATH. Prints constants committed in verify/lines_tests.rs.
"""

import struct
import subprocess


def digest(data):
    return bytes.fromhex(
        subprocess.check_output(["b3sum", "--no-names"], input=data).decode().strip()
    )


def run(ranges, spans):
    data = b"vigil.audit.v1.run-ranges\0" + struct.pack(">I", len(ranges))
    for first, count in ranges:
        data += struct.pack(">QQ", first, count)
    data += struct.pack(">I", len(spans))
    for seg, after, raw in spans:
        data += struct.pack(">IQQ", seg, after, len(raw))
        data += digest(b"vigil.audit.v1.repaired\0" + raw)
    return digest(data).hex()


if __name__ == "__main__":
    for ranges, spans in [
        ([], []),
        ([(4, 2)], []),
        ([(4, 2), (9, 3)], []),
        ([(4, 0)], []),
        ([], [(0, 2**64 - 1, b"not json\n")]),
        ([], [(0, 4, b"not json\n")]),
    ]:
        print(run(ranges, spans))
