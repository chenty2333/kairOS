#!/usr/bin/env bash
#
# push-soak-tag.sh - Push current branch and trigger CI workflows via tag push.
#

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/push-soak-tag.sh [options]

Options:
  --mode <long|short>   CI profile (default: short)
  --long                Shorthand for --mode long
  --short               Shorthand for --mode short
  --remote <name>       Git remote name (default: origin)
  --branch <name>       Branch to push (default: current branch)
  --prefix <text>       Tag prefix (default: soak for long, quick for short)
  --tag <name>          Explicit tag name (skip auto-generated tag)
  --skip-branch-push    Only push tag, skip branch push
  -h, --help            Show help

Examples:
  scripts/push-soak-tag.sh
  scripts/push-soak-tag.sh --long
  scripts/push-soak-tag.sh --short --skip-branch-push
  scripts/push-soak-tag.sh --prefix night
  scripts/push-soak-tag.sh --tag soak-260223-2300
EOF
}

die() {
    echo "push-soak-tag: $*" >&2
    exit 2
}

to_web_url() {
    local remote_url="$1"
    if [[ "${remote_url}" =~ ^git@([^:]+):(.+)\.git$ ]]; then
        echo "https://${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
        return 0
    fi
    if [[ "${remote_url}" =~ ^https?://.+\.git$ ]]; then
        echo "${remote_url%.git}"
        return 0
    fi
    if [[ "${remote_url}" =~ ^https?://.+$ ]]; then
        echo "${remote_url}"
        return 0
    fi
    echo ""
}

remote="origin"
branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
mode="short"
prefix=""
tag=""
push_branch=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            [[ $# -ge 2 ]] || die "--mode requires a value"
            case "$2" in
                long | short)
                    mode="$2"
                    ;;
                *)
                    die "unknown mode: $2 (expected: long|short)"
                    ;;
            esac
            shift 2
            ;;
        --long)
            mode="long"
            shift
            ;;
        --short)
            mode="short"
            shift
            ;;
        --remote)
            [[ $# -ge 2 ]] || die "--remote requires a value"
            remote="$2"
            shift 2
            ;;
        --branch)
            [[ $# -ge 2 ]] || die "--branch requires a value"
            branch="$2"
            shift 2
            ;;
        --prefix)
            [[ $# -ge 2 ]] || die "--prefix requires a value"
            prefix="$2"
            shift 2
            ;;
        --tag)
            [[ $# -ge 2 ]] || die "--tag requires a value"
            tag="$2"
            shift 2
            ;;
        --skip-branch-push)
            push_branch=0
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

if [[ -z "${prefix}" ]]; then
    if [[ "${mode}" == "short" ]]; then
        prefix="quick"
    else
        prefix="soak"
    fi
fi

[[ -n "${branch}" ]] || die "unable to determine current branch"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
    die "must run inside a git repository"
git remote get-url "${remote}" >/dev/null 2>&1 ||
    die "remote '${remote}' does not exist"

if [[ -z "${tag}" ]]; then
    ts="$(date +%y%m%d-%H%M)"
    sha="$(git rev-parse --short HEAD)"
    tag="${prefix}-${ts}-${sha}"
fi

git rev-parse -q --verify "refs/tags/${tag}" >/dev/null 2>&1 &&
    die "local tag already exists: ${tag}"
if git ls-remote --exit-code --tags "${remote}" "refs/tags/${tag}" >/dev/null 2>&1; then
    die "remote tag already exists: ${tag}"
fi

if [[ "${push_branch}" -eq 1 ]]; then
    echo "push-soak-tag: pushing branch ${remote}/${branch}"
    git push "${remote}" "${branch}"
fi

echo "push-soak-tag: creating tag ${tag}"
git tag "${tag}"

echo "push-soak-tag: pushing tag ${remote}/${tag}"
git push "${remote}" "refs/tags/${tag}"

remote_url="$(git remote get-url "${remote}")"
web_url="$(to_web_url "${remote_url}")"
workflow_file=""
workflow_label=""
if [[ "${tag}" == quick-* ]]; then
    workflow_file="ci-quick.yml"
    workflow_label="quick workflow"
elif [[ "${tag}" == soak-* || "${tag}" == night-* ]]; then
    workflow_file="soak-long.yml"
    workflow_label="soak workflow"
fi
echo "push-soak-tag: done"
echo "  mode:   ${mode}"
echo "  branch: ${branch}"
echo "  tag:    ${tag}"
if [[ -n "${web_url}" ]]; then
    echo "  actions: ${web_url}/actions"
    if [[ -n "${workflow_file}" ]]; then
        echo "  ${workflow_label}: ${web_url}/actions/workflows/${workflow_file}"
    else
        echo "  workflow hint: no built-in match for tag prefix"
    fi
fi
