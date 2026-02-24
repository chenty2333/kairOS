#!/usr/bin/env bash
#
# run.sh - Run/test/doctor orchestration.
#

kairos_run_usage() {
    cat <<'EOF'
Usage: scripts/kairos.sh [global options] run <action> [options]

Actions:
  test        Run kernel tests (structured-result first)
              Options: --extra-cflags <flags> --timeout <sec> --log <path>
  test-exec-elf-smoke
              Run exec/ELF smoke regression (interactive shell command path)
              Options: --extra-cflags <flags> --timeout <sec> --log <path>
  test-tcc-smoke
              Run tcc smoke regression (alias of test-exec-elf-smoke)
              Options: --extra-cflags <flags> --timeout <sec> --log <path>
  test-busybox-applets-smoke
              Run busybox applet smoke regression (interactive shell command path)
              Options: --extra-cflags <flags> --timeout <sec> --log <path>
  test-errno-smoke
              Run errno smoke regression (ENOENT/EACCES/ENOEXEC/ENOMEM)
              Options: --extra-cflags <flags> --timeout <sec> --log <path>
  test-soak   Run soak test (expects timeout)
              Options: --extra-cflags <flags> --timeout <sec> --log <path>
  test-debug  Run tests with CONFIG_DEBUG
              Options: --extra-cflags <flags> --timeout <sec> --log <path>
  test-matrix Run SMP x DEBUG test matrix
EOF
}

kairos_doctor_usage() {
    cat <<'EOF'
Usage: scripts/kairos.sh [global options] doctor
EOF
}

kairos_doctor() {
    local qemu
    qemu="$(kairos_arch_to_qemu "${KAIROS_ARCH}")" || kairos_die "unsupported architecture: ${KAIROS_ARCH}"

    local code_src vars_src
    code_src="${UEFI_CODE_SRC:-$(kairos_default_uefi_code_src "${KAIROS_ARCH}")}"
    vars_src="${UEFI_VARS_SRC:-$(kairos_default_uefi_vars_src "${KAIROS_ARCH}")}"

    local failed=0
    for cmd in "$qemu" mke2fs python3; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            kairos_log_error "missing host tool: $cmd"
            failed=1
        fi
    done
    if ! command -v mkfs.fat >/dev/null 2>&1 && ! command -v mkfs.vfat >/dev/null 2>&1; then
        kairos_log_error "missing host tool: mkfs.fat (dosfstools)"
        failed=1
    fi
    if [[ ! -f "$code_src" || ! -f "$vars_src" ]]; then
        kairos_log_error "UEFI firmware not found for ${KAIROS_ARCH}:"
        kairos_log_error "  ${code_src}"
        kairos_log_error "  ${vars_src}"
        failed=1
    fi
    if ((failed)); then
        return 3
    fi

    kairos_log_info "doctor: OK (${KAIROS_ARCH})"
}

kairos_run_clean_kernel_artifacts() {
    local build_dir="${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}"
    rm -rf "${build_dir}/kernel" "${build_dir}/third_party" \
        "${build_dir}/kairos.elf" "${build_dir}/kairos.bin" \
        "${build_dir}/.cflags."*
}

kairos_run_test_once() {
    local extra_cflags="$1"
    local timeout_s="$2"
    local log_path="$3"
    local require_markers="$4"
    local expect_timeout="$5"
    local require_structured="$6"

    local qemu_cmd
    printf -v qemu_cmd \
        'make --no-print-directory -j1 ARCH=%q BUILD_ROOT=%q EXTRA_CFLAGS=%q QEMU_STDIN= RUN_ISOLATED=0 RUN_GC_AUTO=0 UEFI_BOOT_MODE=%q QEMU_UEFI_BOOT_MODE=%q run-direct' \
        "${KAIROS_ARCH}" "${KAIROS_BUILD_ROOT}" "${extra_cflags}" \
        "${UEFI_BOOT_MODE:-}" "${QEMU_UEFI_BOOT_MODE:-}"

    kairos_run_test_locked "${qemu_cmd}" "${timeout_s}" "${log_path}" "${require_markers}" "${expect_timeout}" "" "" "" "${require_structured}" 1
}

kairos_run_test_tcc_smoke_once() {
    local extra_cflags="$1"
    local timeout_s="$2"
    local log_path="$3"
    local boot_delay="${EXEC_ELF_SMOKE_BOOT_DELAY_SEC:-${TCC_SMOKE_BOOT_DELAY_SEC:-8}}"
    local step_delay="${EXEC_ELF_SMOKE_STEP_DELAY_SEC:-${TCC_SMOKE_STEP_DELAY_SEC:-1}}"
    local ready_wait="${EXEC_ELF_SMOKE_READY_WAIT_SEC:-${TCC_SMOKE_READY_WAIT_SEC:-180}}"
    local run_log="${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}/run.log"
    local make_jobs="${KAIROS_JOBS:-$(nproc)}"
    local inner_make_cmd=""
    local smoke_script=""
    local qemu_cmd=""
    local expected_interp="${EXEC_ELF_SMOKE_EXPECTED_INTERP:-${TCC_SMOKE_EXPECTED_INTERP:-}}"
    local expected_interp_strict=0
    if [[ -n "${expected_interp}" ]]; then
        expected_interp_strict=1
    fi
    local required_any=""
    local required_all=""
    local forbidden='Process [0-9]+ killed by signal 11|\\[ERROR\\].*no vma|mm: fault .* no vma|PT_INTERP not supported'

    printf -v required_all 'RC_STATIC:0\nRC_DYN:0\nRC_DYN_HELLO:0\nHELLO_DYN_OK\n__TCC_SMOKE_DONE__'

    printf -v inner_make_cmd \
        'make --no-print-directory -j%q ARCH=%q BUILD_ROOT=%q EXTRA_CFLAGS=%q RUN_ISOLATED=0 RUN_GC_AUTO=0 UEFI_BOOT_MODE=%q QEMU_UEFI_BOOT_MODE=%q' \
        "${make_jobs}" "${KAIROS_ARCH}" "${KAIROS_BUILD_ROOT}" "${extra_cflags}" \
        "${UEFI_BOOT_MODE:-}" "${QEMU_UEFI_BOOT_MODE:-}"

    smoke_script="${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}/exec-elf-smoke-host.sh"
    mkdir -p "$(dirname "${smoke_script}")"
    {
        printf 'run_log=%q\n' "${run_log}"
        printf 'ready_wait=%q\n' "${ready_wait}"
        printf 'boot_delay=%q\n' "${boot_delay}"
        printf 'step_delay=%q\n' "${step_delay}"
        printf 'expected_interp=%q\n' "${expected_interp}"
        printf 'expected_interp_strict=%q\n' "${expected_interp_strict}"
        printf 'inner_make_cmd=%q\n' "${inner_make_cmd}"
        printf 'log_path=%q\n' "${log_path}"
        cat <<'EOF'
: > "$run_log"
fifo="$(mktemp -u /tmp/kairos-exec-elf-smoke.XXXXXX)"
mkfifo "$fifo"
( exec 3<>"$fifo"
for _ in $(seq 1 "$ready_wait"); do
    grep -Eiq 'init: starting shell|BusyBox v' "$run_log" 2>/dev/null && break
    sleep 1
done
sleep "$boot_delay"
printf 'expected_interp="%s"\n' "$expected_interp" >&3
printf 'expected_interp_strict="%s"\n' "$expected_interp_strict" >&3
sleep "$step_delay"
printf 'failed=0\n' >&3
sleep "$step_delay"
printf 'first_fail=""\n' >&3
sleep "$step_delay"
printf 'mark_failed(){ failed=1; if [ -n "${1:-}" ]; then echo SMOKE_FAIL:$1; [ -z "$first_fail" ] && first_fail="$1"; fi; }\n' >&3
sleep "$step_delay"
printf 'classify_exec_fail(){ rc="${1:-1}"; msg="${2:-}"; case "$msg" in *"Permission denied"*) echo exec_perm_denied; return;; *"Exec format error"*|*"not an ELF"*) echo exec_invalid_elf; return;; *"error while loading shared libraries"*|*"Error loading shared library"*) echo exec_missing_shared_object; return;; *"No such file"*|*"not found"*) if [ -n "${expected_interp:-}" ] && [ ! -e "$expected_interp" ]; then echo exec_interp_missing; else echo exec_missing_file_or_so; fi; return;; *"cannot execute"*) echo exec_not_executable; return;; esac; if [ "$rc" -eq 126 ]; then echo exec_perm_denied; elif [ "$rc" -eq 127 ]; then echo exec_missing_file_or_loader; else echo exec_runtime_failed; fi; }\n' >&3
sleep "$step_delay"
printf 'arch="$(uname -m)"\n' >&3
sleep "$step_delay"
printf 'if [ -z "$expected_interp" ]; then\n' >&3
sleep "$step_delay"
printf 'for ld in /lib/ld-musl-${arch}*.so.1 /lib/ld-musl-*.so.1; do [ -e "$ld" ] && { expected_interp="$ld"; break; }; done\n' >&3
sleep "$step_delay"
printf 'fi\n' >&3
sleep "$step_delay"
printf '[ -n "$expected_interp" ] && [ -e "$expected_interp" ] || mark_failed missing_dynamic_loader\n' >&3
sleep "$step_delay"
printf '[ -e /lib/libc.so ] || mark_failed missing_libc_so\n' >&3
sleep "$step_delay"
printf '[ -x /usr/bin/tcc ] || mark_failed missing_tcc_bin\n' >&3
sleep "$step_delay"
printf 'printf '\''int main(void){return 0;}\\n'\'' > /tmp/tcc_smoke_exec.c\n' >&3
sleep "$step_delay"
printf 'tcc -static /tmp/tcc_smoke_exec.c -o /tmp/tcc_smoke_static || mark_failed static_compile_failed\n' >&3
sleep "$step_delay"
printf '[ -x /tmp/tcc_smoke_static ] || mark_failed static_output_missing\n' >&3
sleep "$step_delay"
printf '/tmp/tcc_smoke_static\n' >&3
sleep "$step_delay"
printf 'rc_static=$?\n' >&3
sleep "$step_delay"
printf 'echo RC_STATIC:$rc_static\n' >&3
sleep "$step_delay"
printf '[ "$rc_static" -eq 0 ] || mark_failed static_exec_failed\n' >&3
sleep "$step_delay"
printf 'tcc /tmp/tcc_smoke_exec.c -o /tmp/tcc_smoke_dyn || mark_failed dyn_compile_failed\n' >&3
sleep "$step_delay"
printf '[ -x /tmp/tcc_smoke_dyn ] || mark_failed dyn_output_missing\n' >&3
sleep "$step_delay"
printf 'dyn_err="$(/tmp/tcc_smoke_dyn 2>&1)"; rc_dyn=$?\n' >&3
sleep "$step_delay"
printf 'echo RC_DYN:$rc_dyn\n' >&3
sleep "$step_delay"
printf '[ -z "$dyn_err" ] || echo DYN_ERR:$dyn_err\n' >&3
sleep "$step_delay"
printf 'if [ "$rc_dyn" -ne 0 ]; then dyn_reason="$(classify_exec_fail "$rc_dyn" "$dyn_err")"; mark_failed "$dyn_reason"; fi\n' >&3
sleep "$step_delay"
printf 'tr '\''\\000'\'' '\''\\n'\'' < /tmp/tcc_smoke_dyn > /tmp/tcc_smoke_dyn.str\n' >&3
sleep "$step_delay"
printf 'grep '\''/lib/ld-musl-'\'' /tmp/tcc_smoke_dyn.str > /tmp/tcc_interp.lines\n' >&3
sleep "$step_delay"
printf 'interp_line="$(head -n1 /tmp/tcc_interp.lines)"\n' >&3
sleep "$step_delay"
printf 'echo PT_INTERP:$interp_line\n' >&3
sleep "$step_delay"
printf '[ -n "$interp_line" ] || mark_failed pt_interp_missing\n' >&3
sleep "$step_delay"
printf '[ -n "$interp_line" ] && [ -e "$interp_line" ] || mark_failed pt_interp_unresolvable\n' >&3
sleep "$step_delay"
printf 'if [ "$expected_interp_strict" = "1" ]; then echo "$interp_line" | grep "$expected_interp" >/dev/null 2>&1 || mark_failed pt_interp_mismatch_expected; fi\n' >&3
sleep "$step_delay"
printf 'if [ "$expected_interp_strict" = "1" ]; then [ -e "$expected_interp" ] || mark_failed expected_interp_missing; fi\n' >&3
sleep "$step_delay"
printf 'printf '\''#include <stdio.h>\\nint main(void){puts("hello world");return 0;}\\n'\'' > /tmp/hello.c\n' >&3
sleep "$step_delay"
printf 'tcc /tmp/hello.c -o /tmp/hello_dyn || mark_failed dyn_hello_compile_failed\n' >&3
sleep "$step_delay"
printf '[ -x /tmp/hello_dyn ] || mark_failed dyn_hello_output_missing\n' >&3
sleep "$step_delay"
printf 'hello_out="$(/tmp/hello_dyn 2>&1)"; rc_dyn_hello=$?; echo RC_DYN_HELLO:$rc_dyn_hello; echo HELLO_OUT:$hello_out\n' >&3
sleep "$step_delay"
printf '[ "$rc_dyn_hello" -eq 0 ] || mark_failed dyn_hello_exec_failed\n' >&3
sleep "$step_delay"
printf 'hello_match=0; case "$hello_out" in *"hello world"*) hello_match=1;; esac\n' >&3
sleep "$step_delay"
printf '[ "$hello_match" -eq 1 ] || mark_failed dyn_hello_output_mismatch\n' >&3
sleep "$step_delay"
printf 'if [ "$rc_dyn_hello" -eq 0 ] && [ "$hello_match" -eq 1 ]; then echo HELLO_DYN_OK; fi\n' >&3
sleep "$step_delay"
printf '[ -z "$first_fail" ] || echo SMOKE_FAIL_FIRST:$first_fail\n' >&3
sleep "$step_delay"
printf 'done_tag=__TCC_\n' >&3
sleep "$step_delay"
printf 'done_tag=${done_tag}SMOKE_DONE__\n' >&3
sleep "$step_delay"
printf 'echo TEST_SUMMARY: failed=$failed\n' >&3
sleep "$step_delay"
printf 'json_tag=TEST_RESULT\n' >&3
sleep "$step_delay"
printf 'json_tag=${json_tag}_JSON:\n' >&3
sleep "$step_delay"
printf 'echo "$json_tag {\\"schema_version\\":1,\\"failed\\":$failed,\\"done\\":true,\\"enabled_mask\\":1}"\n' >&3
sleep "$step_delay"
printf 'echo "$done_tag"\n' >&3
sleep "$step_delay"
for _ in $(seq 1 "$ready_wait"); do
    grep -q '__TCC_SMOKE_DONE__' "$log_path" 2>/dev/null && break
    sleep 1
done
printf '\001x' >&3
exec 3>&-
) &
feeder=$!
eval "$inner_make_cmd QEMU_STDIN=\"<$fifo\" run-direct"
rc=$?
wait "$feeder" 2>/dev/null || true
rm -f "$fifo"
exit $rc
EOF
    } > "${smoke_script}"
    chmod +x "${smoke_script}"

    printf -v qemu_cmd \
        'bash %q' \
        "${smoke_script}"

    kairos_run_test_locked "${qemu_cmd}" "${timeout_s}" "${log_path}" 1 0 "${required_any}" "${required_all}" "${forbidden}" 1 0
}

kairos_run_test_busybox_applets_smoke_once() {
    local extra_cflags="$1"
    local timeout_s="$2"
    local log_path="$3"
    local boot_delay="${BUSYBOX_APPLET_SMOKE_BOOT_DELAY_SEC:-8}"
    local step_delay="${BUSYBOX_APPLET_SMOKE_STEP_DELAY_SEC:-1}"
    local ready_wait="${BUSYBOX_APPLET_SMOKE_READY_WAIT_SEC:-180}"
    local run_log="${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}/run.log"
    local make_jobs="${KAIROS_JOBS:-$(nproc)}"
    local applet_list="base32 base64 cksum crc32 md5sum sha1sum sha256sum sha3sum sha512sum sum dos2unix expand fsync hostid install less link logname more nohup nproc printenv shuf split tac timeout truncate tsort unexpand unix2dos unlink watch xxd ar cpio gunzip gzip tar unzip zcat"
    local -a applet_items=()
    local expected_count=0
    local inner_make_cmd=""
    local smoke_script=""
    local qemu_cmd=""
    local required_any=""
    local required_all=""
    local forbidden='Process [0-9]+ killed by signal 11|\\[ERROR\\].*no vma|mm: fault .* no vma'

    read -r -a applet_items <<< "${applet_list}"
    expected_count="${#applet_items[@]}"
    required_any="APPLET_SMOKE_OK:${expected_count}"

    printf -v inner_make_cmd \
        'make --no-print-directory -j%q ARCH=%q BUILD_ROOT=%q EXTRA_CFLAGS=%q RUN_ISOLATED=0 RUN_GC_AUTO=0 UEFI_BOOT_MODE=%q QEMU_UEFI_BOOT_MODE=%q' \
        "${make_jobs}" "${KAIROS_ARCH}" "${KAIROS_BUILD_ROOT}" "${extra_cflags}" \
        "${UEFI_BOOT_MODE:-}" "${QEMU_UEFI_BOOT_MODE:-}"

    printf -v required_all 'APPLET_SMOKE_OK:%s\nAPPLET_BAD_COUNT:0\n__BB_APPLET_SMOKE_DONE__' \
        "${expected_count}"

    smoke_script="${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}/busybox-applets-smoke-host.sh"
    mkdir -p "$(dirname "${smoke_script}")"
    {
        printf 'run_log=%q\n' "${run_log}"
        printf 'ready_wait=%q\n' "${ready_wait}"
        printf 'boot_delay=%q\n' "${boot_delay}"
        printf 'step_delay=%q\n' "${step_delay}"
        printf 'applet_list=%q\n' "${applet_list}"
        printf 'expected_count=%q\n' "${expected_count}"
        printf 'inner_make_cmd=%q\n' "${inner_make_cmd}"
        printf 'log_path=%q\n' "${log_path}"
        cat <<'EOF'
: > "$run_log"
fifo="$(mktemp -u /tmp/kairos-bb-applet-smoke.XXXXXX)"
mkfifo "$fifo"
( exec 3<>"$fifo"
for _ in $(seq 1 "$ready_wait"); do
    grep -Eiq 'init: starting shell|BusyBox v' "$run_log" 2>/dev/null && break
    sleep 1
done
sleep "$boot_delay"
printf 'bad=0; for a in %s; do if [ ! -x "/bin/$a" ]; then bad=$((bad+1)); echo APPLET_BAD_ITEM:missing:$a; continue; fi; "/bin/$a" --help </dev/null >/dev/null 2>&1; rc=$?; if [ "$rc" -gt 128 ]; then bad=$((bad+1)); echo APPLET_BAD_ITEM:rc:$a:$rc; fi; done; echo APPLET_SMOKE_OK:%s; echo APPLET_BAD_COUNT:$bad; echo TEST_SUMMARY: failed=$bad; echo TEST_RESULT_JSON: {\"schema_version\":1,\"failed\":$bad,\"done\":true,\"enabled_mask\":1}; echo __BB_APPLET_SMOKE_DONE__\n' "$applet_list" "$expected_count" >&3
sleep "$step_delay"
for _ in $(seq 1 "$ready_wait"); do
    grep -q '__BB_APPLET_SMOKE_DONE__' "$log_path" 2>/dev/null && break
    sleep 1
done
printf '\001x' >&3
exec 3>&-
) &
feeder=$!
eval "$inner_make_cmd QEMU_STDIN=\"<$fifo\" run-direct"
rc=$?
wait "$feeder" 2>/dev/null || true
rm -f "$fifo"
exit $rc
EOF
    } > "${smoke_script}"
    chmod +x "${smoke_script}"

    printf -v qemu_cmd \
        'bash %q' \
        "${smoke_script}"

    kairos_run_test_locked "${qemu_cmd}" "${timeout_s}" "${log_path}" 0 1 "${required_any}" "${required_all}" "${forbidden}" 1 0
}

kairos_run_test_errno_smoke_once() {
    local extra_cflags="$1"
    local timeout_s="$2"
    local log_path="$3"
    local boot_delay="${ERRNO_SMOKE_BOOT_DELAY_SEC:-8}"
    local ready_wait="${ERRNO_SMOKE_READY_WAIT_SEC:-180}"
    local run_log="${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}/run.log"
    local make_jobs="${KAIROS_JOBS:-$(nproc)}"
    local inner_make_cmd=""
    local smoke_script=""
    local qemu_cmd=""
    local required_any="ERRNO_SMOKE_OK"
    local required_all=""
    local forbidden='Process [0-9]+ killed by signal 11|\\[ERROR\\].*no vma|mm: fault .* no vma'

    printf -v inner_make_cmd \
        'make --no-print-directory -j%q ARCH=%q BUILD_ROOT=%q EXTRA_CFLAGS=%q RUN_ISOLATED=0 RUN_GC_AUTO=0 UEFI_BOOT_MODE=%q QEMU_UEFI_BOOT_MODE=%q' \
        "${make_jobs}" "${KAIROS_ARCH}" "${KAIROS_BUILD_ROOT}" "${extra_cflags}" \
        "${UEFI_BOOT_MODE:-}" "${QEMU_UEFI_BOOT_MODE:-}"

    printf -v required_all 'ERRNO_CASE:ENOENT:OK\nERRNO_CASE:EACCES:OK\nERRNO_CASE:ENOEXEC:OK\nERRNO_CASE:ENOMEM:OK\nERRNO_SMOKE_OK\n__ERRNO_SMOKE_DONE__'

    smoke_script="${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}/errno-smoke-host.sh"
    mkdir -p "$(dirname "${smoke_script}")"
    {
        printf 'run_log=%q\n' "${run_log}"
        printf 'ready_wait=%q\n' "${ready_wait}"
        printf 'boot_delay=%q\n' "${boot_delay}"
        printf 'inner_make_cmd=%q\n' "${inner_make_cmd}"
        printf 'log_path=%q\n' "${log_path}"
        cat <<'EOF'
: > "$run_log"
fifo="$(mktemp -u /tmp/kairos-errno-smoke.XXXXXX)"
mkfifo "$fifo"
( exec 3<>"$fifo"
for _ in $(seq 1 "$ready_wait"); do
    grep -Eiq 'init: starting shell|BusyBox v' "$run_log" 2>/dev/null && break
    sleep 1
done
sleep "$boot_delay"
cat >&3 <<'GUEST_CMDS'
cat >/tmp/errno_smoke.c <<'EOF_C'
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int write_file_exact(const char *path, const char *data, mode_t mode) {
    size_t len = strlen(data);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0)
        return errno ? errno : EIO;
    ssize_t wr = write(fd, data, len);
    int saved = errno;
    close(fd);
    if (wr < 0 || (size_t)wr != len)
        return saved ? saved : EIO;
    if (chmod(path, mode) < 0)
        return errno ? errno : EIO;
    return 0;
}

static int check_enoent(void) {
    errno = 0;
    int fd = open("/tmp/.errno-smoke.missing", O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return 1001;
    }
    return (errno == ENOENT) ? 0 : (errno ? errno : 1002);
}

static int check_eacces(void) {
    const char *path = "/tmp/errno_eacces.sh";
    int wret = write_file_exact(path, "#!/bin/sh\nexit 0\n", 0644);
    if (wret != 0)
        return wret;
    char *const argv[] = { (char *)path, NULL };
    char *const envp[] = { NULL };
    errno = 0;
    execve(path, argv, envp);
    return (errno == EACCES) ? 0 : (errno ? errno : 1101);
}

static int check_enoexec(void) {
    const char *path = "/tmp/errno_enoexec.bin";
    int wret = write_file_exact(path, "not-an-elf\n", 0755);
    if (wret != 0)
        return wret;
    char *const argv[] = { (char *)path, NULL };
    char *const envp[] = { NULL };
    errno = 0;
    execve(path, argv, envp);
    return (errno == ENOEXEC) ? 0 : (errno ? errno : 1201);
}

static int check_enomem(void) {
    size_t huge_len = (size_t)0x3ff0000000ULL;
    errno = 0;
    void *p = mmap(NULL, huge_len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) {
        (void)munmap(p, huge_len);
        return 1301;
    }
    return (errno == ENOMEM) ? 0 : (errno ? errno : 1302);
}

static int report_case(const char *name, int rc) {
    if (rc == 0) {
        printf("ERRNO_CASE:%s:OK\n", name);
        return 0;
    }
    printf("ERRNO_CASE:%s:FAIL:%d\n", name, rc);
    printf("SMOKE_FAIL:%s\n", name);
    return 1;
}

int main(void) {
    int failed = 0;
    failed += report_case("ENOENT", check_enoent());
    failed += report_case("EACCES", check_eacces());
    failed += report_case("ENOEXEC", check_enoexec());
    failed += report_case("ENOMEM", check_enomem());
    if (failed == 0)
        printf("ERRNO_SMOKE_OK\n");
    printf("TEST_SUMMARY: failed=%d\n", failed);
    printf("TEST_RESULT_JSON: {\"schema_version\":1,\"failed\":%d,\"done\":true,\"enabled_mask\":1}\n", failed);
    printf("__ERRNO_SMOKE_DONE__\n");
    return failed ? 1 : 0;
}
EOF_C
if ! tcc -static /tmp/errno_smoke.c -o /tmp/errno_smoke; then
    echo SMOKE_FAIL:compile_errno_smoke
    echo TEST_SUMMARY: failed=1
    echo 'TEST_RESULT_JSON: {"schema_version":1,"failed":1,"done":true,"enabled_mask":1}'
    echo __ERRNO_SMOKE_DONE__
else
    /tmp/errno_smoke
fi
GUEST_CMDS
for _ in $(seq 1 "$ready_wait"); do
    grep -q '__ERRNO_SMOKE_DONE__' "$log_path" 2>/dev/null && break
    sleep 1
done
printf '\001x' >&3
exec 3>&-
) &
feeder=$!
eval "$inner_make_cmd QEMU_STDIN=\"<$fifo\" run-direct"
rc=$?
wait "$feeder" 2>/dev/null || true
rm -f "$fifo"
exit $rc
EOF
    } > "${smoke_script}"
    chmod +x "${smoke_script}"

    printf -v qemu_cmd \
        'bash %q' \
        "${smoke_script}"

    kairos_run_test_locked "${qemu_cmd}" "${timeout_s}" "${log_path}" 0 1 "${required_any}" "${required_all}" "${forbidden}" 1 0
}

kairos_run_test_locked() {
    local qemu_cmd="$1"
    local timeout_s="$2"
    local log_path="$3"
    local require_markers="$4"
    local expect_timeout="$5"
    local required_marker_regex="${6:-}"
    local required_markers_all="${7:-}"
    local forbidden_marker_regex="${8:-}"
    local require_structured="${9:-1}"
    local clean_artifacts="${10:-1}"
    local test_lock_file="${TEST_LOCK_FILE:-${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}/.locks/test.lock}"

    if [[ "${clean_artifacts}" -eq 1 ]]; then
        kairos_run_clean_kernel_artifacts
    fi

    local rc=0
    set +e
    (
        cd "${KAIROS_ROOT_DIR}"
        kairos_exec_script_env "test" \
            QEMU_CMD="${qemu_cmd}" \
            QEMU_EXTRA="" \
            UEFI_BOOT_MODE="${UEFI_BOOT_MODE:-}" \
            QEMU_UEFI_BOOT_MODE="${QEMU_UEFI_BOOT_MODE:-}" \
            TEST_TIMEOUT="${timeout_s}" \
            TEST_LOG="${log_path}" \
            TEST_REQUIRE_MARKERS="${require_markers}" \
            TEST_EXPECT_TIMEOUT="${expect_timeout}" \
            TEST_REQUIRE_STRUCTURED="${require_structured}" \
            TEST_REQUIRED_MARKER_REGEX="${required_marker_regex}" \
            TEST_REQUIRED_MARKERS_ALL="${required_markers_all}" \
            TEST_FORBIDDEN_MARKER_REGEX="${forbidden_marker_regex}" \
            TEST_BUILD_ROOT="${KAIROS_BUILD_ROOT}" \
            TEST_ARCH="${KAIROS_ARCH}" \
            TEST_RUN_ID="${RUN_ID:-}" \
            TEST_LOCK_FILE="${test_lock_file}" \
            "${KAIROS_ROOT_DIR}/scripts/run-qemu-test.sh"
    )
    rc=$?
    set -e

    if [[ "${clean_artifacts}" -eq 1 ]]; then
        kairos_run_clean_kernel_artifacts
    fi
    return "$rc"
}

kairos_run_parse_common_opts() {
    local -n _extra_ref="$1"
    local -n _timeout_ref="$2"
    local -n _log_ref="$3"
    shift 3

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --extra-cflags)
                [[ $# -ge 2 ]] || kairos_die "--extra-cflags requires a value"
                _extra_ref="$2"
                shift 2
                ;;
            --timeout)
                [[ $# -ge 2 ]] || kairos_die "--timeout requires a value"
                _timeout_ref="$2"
                shift 2
                ;;
            --log)
                [[ $# -ge 2 ]] || kairos_die "--log requires a value"
                _log_ref="$2"
                shift 2
                ;;
            *)
                kairos_die "unknown run option: $1"
                ;;
        esac
    done
}

kairos_run_dispatch() {
    local action="${1:-}"
    shift || true

    if [[ -z "$action" ]]; then
        kairos_run_usage
        return 2
    fi

    local default_extra="${TEST_EXTRA_CFLAGS:--DCONFIG_KERNEL_TESTS=1}"
    local extra timeout_s log_path

    case "$action" in
        test)
            extra="$default_extra"
            timeout_s="${TEST_TIMEOUT:-180}"
            log_path="${TEST_LOG:-${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}/test.log}"
            kairos_run_parse_common_opts extra timeout_s log_path "$@"
            kairos_run_test_once "$extra" "$timeout_s" "$log_path" 1 0 1
            ;;
        test-exec-elf-smoke)
            extra="${EXEC_ELF_SMOKE_EXTRA_CFLAGS:-${TCC_SMOKE_EXTRA_CFLAGS:-}}"
            timeout_s="${EXEC_ELF_SMOKE_TIMEOUT:-${TCC_SMOKE_TIMEOUT:-240}}"
            log_path="${EXEC_ELF_SMOKE_LOG:-${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}/exec-elf-smoke.log}"
            kairos_run_parse_common_opts extra timeout_s log_path "$@"
            kairos_run_test_tcc_smoke_once "$extra" "$timeout_s" "$log_path"
            ;;
        test-tcc-smoke)
            extra="${TCC_SMOKE_EXTRA_CFLAGS:-${EXEC_ELF_SMOKE_EXTRA_CFLAGS:-}}"
            timeout_s="${TCC_SMOKE_TIMEOUT:-${EXEC_ELF_SMOKE_TIMEOUT:-240}}"
            log_path="${TCC_SMOKE_LOG:-${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}/tcc-smoke.log}"
            kairos_run_parse_common_opts extra timeout_s log_path "$@"
            kairos_run_test_tcc_smoke_once "$extra" "$timeout_s" "$log_path"
            ;;
        test-busybox-applets-smoke)
            extra="${BUSYBOX_APPLET_SMOKE_EXTRA_CFLAGS:-}"
            timeout_s="${BUSYBOX_APPLET_SMOKE_TIMEOUT:-240}"
            log_path="${BUSYBOX_APPLET_SMOKE_LOG:-${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}/busybox-applets-smoke.log}"
            kairos_run_parse_common_opts extra timeout_s log_path "$@"
            kairos_run_test_busybox_applets_smoke_once "$extra" "$timeout_s" "$log_path"
            ;;
        test-errno-smoke)
            extra="${ERRNO_SMOKE_EXTRA_CFLAGS:-}"
            timeout_s="${ERRNO_SMOKE_TIMEOUT:-240}"
            log_path="${ERRNO_SMOKE_LOG:-${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}/errno-smoke.log}"
            kairos_run_parse_common_opts extra timeout_s log_path "$@"
            kairos_run_test_errno_smoke_once "$extra" "$timeout_s" "$log_path"
            ;;
        test-soak)
            extra="${SOAK_EXTRA_CFLAGS:--DCONFIG_PMM_PCP_MODE=2}"
            timeout_s="${SOAK_TIMEOUT:-600}"
            log_path="${SOAK_LOG:-${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}/soak.log}"
            kairos_run_parse_common_opts extra timeout_s log_path "$@"
            kairos_run_test_once "$extra" "$timeout_s" "$log_path" 0 1 0
            ;;
        test-debug)
            extra="${default_extra} -DCONFIG_DEBUG=1"
            timeout_s="${TEST_TIMEOUT:-180}"
            log_path="${TEST_LOG:-${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}/test.log}"
            kairos_run_parse_common_opts extra timeout_s log_path "$@"
            kairos_run_test_once "$extra" "$timeout_s" "$log_path" 1 0 1
            ;;
        test-matrix)
            (
                cd "${KAIROS_ROOT_DIR}"
                kairos_exec_script_env "test-matrix" \
                    ARCH="${KAIROS_ARCH}" \
                    BUILD_ROOT="${KAIROS_BUILD_ROOT}" \
                    CPUS="${CPUS:-1 2 4}" \
                    DEBUG_LEVELS="${DEBUG_LEVELS:-0 1}" \
                    bash "${KAIROS_ROOT_DIR}/scripts/test-matrix.sh"
            )
            ;;
        *)
            kairos_die "unknown run action: ${action}"
            ;;
    esac
}
