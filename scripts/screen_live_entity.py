"""Screen Live Entity on Studionet via GenLayer Multi-Validator Consensus.

Author: vix
Triggers web fetching of official authoritative sources, LLM compliance analysis,
and equivalence consensus on the canonical contract.
"""

import subprocess
import sys

CONTRACT_ADDRESS = "0x74eeB7232EBa3F55006D21BbF61A7e223517E350"
RPC_URL = "https://studio.genlayer.com/api"


def main():
    print(f"Screening entity #1 on contract {CONTRACT_ADDRESS}...")
    cmd = [
        "genlayer.cmd",
        "write",
        CONTRACT_ADDRESS,
        "screen_entity",
        "--rpc",
        RPC_URL,
        "--args",
        "1",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    print("STDOUT:")
    print(res.stdout)
    if res.returncode != 0:
        print("STDERR:", file=sys.stderr)
        print(res.stderr, file=sys.stderr)
        sys.exit(res.returncode)


if __name__ == "__main__":
    main()
