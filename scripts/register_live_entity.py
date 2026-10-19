"""Register Live Entity on Studionet for ComplianceSanctionsSentinel v1.1.0.

Author: vix
Submits target entity registration transaction to the canonical contract with
verified authoritative regulatory gazette provenance.
"""

import subprocess
import json
import sys

CONTRACT_ADDRESS = "0x74eeB7232EBa3F55006D21BbF61A7e223517E350"
RPC_URL = "https://studio.genlayer.com/api"

name = "Ethereum Foundation"
jurisdiction = "Switzerland"
identifier = "CHE-497.042.846"
source_urls_json = '["https://www.seco.admin.ch/seco/en/home/Aussenwirtschaftspolitik_Wirtschaftliche_Zusammenarbeit/Wirtschaftsbeziehungen/exportkontrollen-und-sanktionen/sanktionen-embargos.html"]'
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
    res = subprocess.run(cmd, capture_output=True, text=True)
    print("STDOUT:")
    print(res.stdout)
    if res.returncode != 0:
        print("STDERR:", file=sys.stderr)
        print(res.stderr, file=sys.stderr)
        sys.exit(res.returncode)


if __name__ == "__main__":
    main()
