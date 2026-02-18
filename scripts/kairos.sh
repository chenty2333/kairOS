#!/usr/bin/env bash
#
# kairos.sh - Unified orchestration entrypoint for Kairos scripts.
#

set -euo pipefail

KAIROS_ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${KAIROS_ROOT_DIR}/scripts/lib/common.sh"
source "${KAIROS_ROOT_DIR}/scripts/lib/log.sh"
source "${KAIROS_ROOT_DIR}/scripts/lib/env.sh"
source "${KAIROS_ROOT_DIR}/scripts/lib/cmd.sh"
source "${KAIROS_ROOT_DIR}/scripts/modules/toolchain.sh"
source "${KAIROS_ROOT_DIR}/scripts/modules/image.sh"
source "${KAIROS_ROOT_DIR}/scripts/modules/deps.sh"
source "${KAIROS_ROOT_DIR}/scripts/modules/run.sh"

KAIROS_ARCH="${ARCH:-riscv64}"
KAIROS_QUIET="${QUIET:-0}"
KAIROS_VERBOSE=0
KAIROS_JOBS="${JOBS:-$(nproc)}"

kairos_usage() {
    cat <<'EOF'
Usage: scripts/kairos.sh [global options] <command> [args]

Global options:
  --arch <arch>   Target arch (riscv64|x86_64|aarch64)
  --quiet         Quiet mode
  --verbose       Verbose command echo
  --jobs <n>      Parallel jobs for build scripts
  -h, --help      Show help

Commands:
  toolchain <action>  Toolchain/userland build actions
  image <action>      Image assembly actions
  run <action>        Test/run helper actions
  deps <action>       Dependency fetch actions
  doctor              Host dependency checks
EOF
}

if [[ $# -eq 0 ]]; then
    kairos_usage
    exit 2
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            [[ $# -ge 2 ]] || kairos_die "--arch requires a value"
            KAIROS_ARCH="$2"
            shift 2
            ;;
        --quiet)
            KAIROS_QUIET=1
            shift
            ;;
        --verbose)
            KAIROS_VERBOSE=1
            KAIROS_QUIET=0
            shift
            ;;
        --jobs)
            [[ $# -ge 2 ]] || kairos_die "--jobs requires a value"
            KAIROS_JOBS="$2"
            shift 2
            ;;
        -h | --help)
            kairos_usage
            exit 0
            ;;
        toolchain | image | run | deps | doctor | help)
            break
            ;;
        *)
            kairos_die "unknown option or command: $1"
            ;;
    esac
done

[[ $# -gt 0 ]] || kairos_die "missing command"
kairos_require_arch "$KAIROS_ARCH"
export KAIROS_ROOT_DIR KAIROS_ARCH KAIROS_QUIET KAIROS_VERBOSE KAIROS_JOBS

command="$1"
shift

case "$command" in
    toolchain)
        kairos_toolchain_dispatch "$@"
        ;;
    image)
        kairos_image_dispatch "$@"
        ;;
    run)
        kairos_run_dispatch "$@"
        ;;
    deps)
        kairos_deps_dispatch "$@"
        ;;
    help)
        if [[ $# -gt 0 ]]; then
            kairos_usage
            exit 2
        fi
        kairos_usage
        ;;
    doctor)
        if [[ $# -gt 0 ]]; then
            kairos_doctor_usage
            exit 2
        fi
        kairos_doctor
        ;;
    *)
        kairos_die "unknown command: ${command}"
        ;;
esac
