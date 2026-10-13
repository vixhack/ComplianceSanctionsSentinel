"""Register Live Entity on Studionet for ComplianceSanctionsSentinel v1.0.1.

Author: vix
Submits target entity registration transaction to the canonical contract.
"""

import subprocess
import json
import sys

CONTRACT_ADDRESS = "0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53"
RPC_URL = "https://studio.genlayer.com/api"

name = "Ethereum Foundation"
jurisdiction = "Switzerland"
identifier = "CHE-497.042.846"
source_urls_json = '["https://raw.githubusercontent.com/github/gitignore/main/Python.gitignore"]'
regime = "SWISS_SECO"


def main():
    print(f"Registering entity on contract {CONTRACT_ADDRESS}...")
    cmd = [
        "genlayer.cmd",
        "write",
        CONTRACT_ADDRESS,
        "register_entity",
        "--rpc",
        RPC_URL,
        "--args",
        name,
        jurisdiction,
        identifier,
        source_urls_json,
        regime,
    ]
    # Do not use shell=True so argument boundaries are strictly preserved by Windows CreateProcess
    res = subprocess.run(cmd, capture_output=True, text=True)
    print("STDOUT:")
    print(res.stdout)
    if res.returncode != 0:
        print("STDERR:", file=sys.stderr)
        print(res.stderr, file=sys.stderr)
        sys.exit(res.returncode)


if __name__ == "__main__":
    main()
