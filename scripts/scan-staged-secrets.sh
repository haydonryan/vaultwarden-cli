#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

failed=0

report_issue() {
  local path="$1"
  local reason="$2"
  failed=1
  printf 'Potential secret detected in %s: %s\n' "$path" "$reason" >&2
}

looks_like_template() {
  local value="$1"
  [[ "$value" =~ (^|/|\.)(example|examples|sample|samples|template|templates|fixture|fixtures|testdata|mock)(/|\.|_|-|$) ]]
}

check_filename_risk() {
  local path="$1"
  local base_name="${path##*/}"

  if looks_like_template "$path"; then
    return
  fi

  case "$base_name" in
    .env|.env.*|*.pem|*.p12|*.pfx|*.jks|*.ovpn|*.key|id_rsa|id_dsa|credentials.json|secrets.json)
      report_issue "$path" "sensitive file name staged"
      ;;
  esac
}

scan_file_contents() {
  local path="$1"
  local scratch_name="${path//\//__}"
  local scratch_file="$tmp_dir/$scratch_name"

  git show ":$path" > "$scratch_file" 2>/dev/null || return

  if [ ! -s "$scratch_file" ]; then
    return
  fi

  if ! LC_ALL=C grep -Iq . "$scratch_file"; then
    return
  fi

  if LC_ALL=C grep -Eq -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----' "$scratch_file"; then
    report_issue "$path" "private key material"
  fi

  if LC_ALL=C grep -Eq '\b(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b' "$scratch_file"; then
    report_issue "$path" "AWS access key pattern"
  fi

  if LC_ALL=C grep -Eq '\bgh[pousr]_[A-Za-z0-9_]{20,255}\b' "$scratch_file"; then
    report_issue "$path" "GitHub token pattern"
  fi

  if LC_ALL=C grep -Eq '\bxox[baprs]-[A-Za-z0-9-]{10,}\b' "$scratch_file"; then
    report_issue "$path" "Slack token pattern"
  fi

  if LC_ALL=C grep -Eq '\b(sk|rk)_live_[A-Za-z0-9]{16,}\b' "$scratch_file"; then
    report_issue "$path" "Stripe live key pattern"
  fi

  while IFS=: read -r line_no line; do
    lowered_line="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
    case "$lowered_line" in
      *example*|*sample*|*template*|*placeholder*|*changeme*|*dummy*|*fake*|*todo*|*your_*|*your-*|*\<*|*\$\{*|*secrets-ignore* )
        continue
        ;;
    esac
    report_issue "$path" "credential-like assignment on line $line_no"
  done < <(
    LC_ALL=C grep -Ein '\b(api[-_ ]?key|secret|token|password|passwd|pwd|client[-_ ]?secret|access[-_ ]?key)\b[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9/+._=-]{16,}["'"'"']?' "$scratch_file" || true
  )
}

while IFS= read -r -d '' path; do
  check_filename_risk "$path"
  scan_file_contents "$path"
done < <(git diff --cached --name-only --diff-filter=ACMR -z)

if [ "$failed" -ne 0 ]; then
  cat >&2 <<'EOF'
Commit blocked because staged changes look like they contain secrets.
Remove or rotate the secret before committing.
EOF
  exit 1
fi
