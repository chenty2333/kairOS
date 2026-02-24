#!/usr/bin/env bash

set -euo pipefail

ARCH="${ARCH:-riscv64}"
TEST_TARGET="${TEST_TARGET:-test-vfs-ipc}"
TEST_CONCURRENCY="${TEST_CONCURRENCY:-3}"
TEST_ROUNDS="${TEST_ROUNDS:-3}"
TEST_TIMEOUT="${TEST_TIMEOUT:-300}"
MAKE_CMD="${MAKE_CMD:-make}"

if ! [[ "${TEST_CONCURRENCY}" =~ ^[0-9]+$ ]] || [[ "${TEST_CONCURRENCY}" -le 0 ]]; then
    echo "test-concurrent: TEST_CONCURRENCY must be a positive integer" >&2
    exit 2
fi
if ! [[ "${TEST_ROUNDS}" =~ ^[0-9]+$ ]] || [[ "${TEST_ROUNDS}" -le 0 ]]; then
    echo "test-concurrent: TEST_ROUNDS must be a positive integer" >&2
    exit 2
fi
if ! [[ "${TEST_TIMEOUT}" =~ ^[0-9]+$ ]] || [[ "${TEST_TIMEOUT}" -le 0 ]]; then
    echo "test-concurrent: TEST_TIMEOUT must be a positive integer" >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "test-concurrent: python3 is required" >&2
    exit 2
fi

tmp_root="$(mktemp -d /tmp/kairos-test-concurrent.XXXXXX)"
trap 'rm -rf "${tmp_root}"' EXIT

overall_total=0
overall_pass=0
overall_fail=0
overall_infra=0
overall_error=0
overall_timeout=0

echo "test-concurrent: arch=${ARCH} target=${TEST_TARGET} concurrency=${TEST_CONCURRENCY} rounds=${TEST_ROUNDS} timeout=${TEST_TIMEOUT}s"
echo "test-concurrent: workdir=${tmp_root}"

for round in $(seq 1 "${TEST_ROUNDS}"); do
    round_dir="${tmp_root}/round-${round}"
    mkdir -p "${round_dir}"
    echo
    echo "=== round ${round}/${TEST_ROUNDS} ==="

    declare -a pids=()
    for idx in $(seq 1 "${TEST_CONCURRENCY}"); do
        (
            set +e
            "${MAKE_CMD}" --no-print-directory ARCH="${ARCH}" TEST_TIMEOUT="${TEST_TIMEOUT}" -j1 "${TEST_TARGET}" \
                >"${round_dir}/job-${idx}.log" 2>&1
            cmd_rc=$?
            echo "${cmd_rc}" >"${round_dir}/job-${idx}.rc"
            exit 0
        ) &
        pids+=("$!")
    done

    for pid in "${pids[@]}"; do
        wait "${pid}" || true
    done

    round_pass=0
    round_fail=0
    round_infra=0
    round_error=0
    round_timeout=0

    for idx in $(seq 1 "${TEST_CONCURRENCY}"); do
        log="${round_dir}/job-${idx}.log"
        rc_file="${round_dir}/job-${idx}.rc"
        rc="NA"
        if [[ -f "${rc_file}" ]]; then
            rc="$(cat "${rc_file}")"
        fi

        result_path="$(sed -n 's/^test: result -> //p' "${log}" | tail -n 1)"
        manifest_path="$(sed -n 's/^test: manifest -> //p' "${log}" | tail -n 1)"
        run_id="-"
        if [[ -n "${manifest_path}" ]]; then
            run_id="$(basename "$(dirname "${manifest_path}")")"
        fi

        status="missing_result"
        reason="missing_result"
        if [[ -n "${result_path}" && -f "${result_path}" ]]; then
            read -r status reason < <(
                python3 - "${result_path}" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as fp:
        obj = json.load(fp)
    status = str(obj.get("status", "unknown"))
    reason = str(obj.get("reason", "unknown"))
    print(f"{status} {reason}")
except Exception:
    print("invalid_result_json invalid_result_json")
PY
            )
        fi

        case "${status}" in
            pass)
                round_pass=$((round_pass + 1))
                ;;
            infra_fail)
                round_infra=$((round_infra + 1))
                ;;
            error)
                round_error=$((round_error + 1))
                ;;
            timeout)
                round_timeout=$((round_timeout + 1))
                ;;
            *)
                round_fail=$((round_fail + 1))
                ;;
        esac

        echo "  job=${idx} rc=${rc} status=${status} reason=${reason} run_id=${run_id}"
    done

    round_total="${TEST_CONCURRENCY}"
    overall_total=$((overall_total + round_total))
    overall_pass=$((overall_pass + round_pass))
    overall_fail=$((overall_fail + round_fail))
    overall_infra=$((overall_infra + round_infra))
    overall_error=$((overall_error + round_error))
    overall_timeout=$((overall_timeout + round_timeout))

    echo "round summary: pass=${round_pass} fail=${round_fail} infra_fail=${round_infra} error=${round_error} timeout=${round_timeout}"
done

echo
echo "=== concurrent summary ==="
echo "total=${overall_total} pass=${overall_pass} fail=${overall_fail} infra_fail=${overall_infra} error=${overall_error} timeout=${overall_timeout}"

if [[ "${overall_pass}" -eq "${overall_total}" ]]; then
    echo "test-concurrent: PASS"
    exit 0
fi

echo "test-concurrent: FAIL"
exit 1
