#!/usr/bin/env bash
#
# Filter known non-fatal UEFI/EDK2 boot noise from QEMU console output.
#

set -euo pipefail

awk '
/ArmTrngLib could not be correctly initialized\./ { next }
/Tpm2SubmitCommand - Tcg2 - Not Found/ { next }
/Tpm2GetCapabilityPcrs fail!/ { next }
/ConvertPages:/ { next }
{
    print
    fflush()
}
'
