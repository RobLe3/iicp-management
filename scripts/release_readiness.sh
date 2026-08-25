#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${1:-$ROOT/target/release-readiness}"
fail() { printf 'release readiness failed: %s\n' "$*" >&2; exit 1; }
cleanup_dir="$(mktemp -d)"
cleanup() { python3 - "$cleanup_dir" <<'PY'
import shutil,sys
shutil.rmtree(sys.argv[1],ignore_errors=True)
PY
}
trap cleanup EXIT

cd "$ROOT"
[[ "$(git branch --show-current)" == "main" ]] || fail "current branch is not main"
git diff --quiet && git diff --cached --quiet || fail "worktree is dirty"
head="$(git rev-parse HEAD)"
[[ "$head" == "$(git rev-parse origin/main)" ]] || fail "HEAD does not match origin/main"
version="$(python3 - <<'PY'
import tomllib
print(tomllib.load(open('Cargo.toml','rb'))['package']['version'])
PY
)"
tag="v$version"
[[ -z "$(git tag --list "$tag")" ]] || fail "tag $tag already exists locally"
if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then fail "tag $tag already exists on origin"; fi
command -v cargo-audit >/dev/null || fail "cargo-audit 0.22.2 is required"
[[ "$(cargo audit --version)" == *"0.22.2"* ]] || fail "cargo-audit 0.22.2 is required"

python3 scripts/check_dependency_policy.py
python3 -m unittest scripts/test_dependency_policy.py scripts/test_release_manifest.py scripts/test_release_readiness.py
cargo metadata --locked --format-version 1 >/dev/null
advisory="$cleanup_dir/advisory-db"
git clone --quiet --depth 1 https://github.com/RustSec/advisory-db.git "$advisory"
cargo audit --no-fetch --db "$advisory"
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo package --locked

crate="$ROOT/target/package/iicp-management-core-$version.crate"
[[ -f "$crate" ]] || fail "packaged crate not found"
listing="$cleanup_dir/package.list"
tar -tzf "$crate" >"$listing"
for required in Cargo.lock Cargo.toml README.md COMPATIBILITY.md CHANGELOG.md CONFORMANCE.md LICENSE "docs/RELEASE_NOTES_$version.md"; do
  grep -Eq "/${required}$" "$listing" || fail "package is missing $required"
done
for required in contracts/management-profile-v1.schema.json fixtures/management-profile-conformance-v1.json examples/finance/management-profile.json docs/ADR-008-single-crate-developer-preview-release.md contracts/diagnostic-bundle-v1.schema.json fixtures/diagnostic-bundle-conformance-v1.json docs/ADR-009-diagnostic-bundles-are-minimized-evidence.md docs/DIAGNOSTIC_BUNDLE_WORKFLOW.md docs/LOCAL_MANAGEMENT_EVALUATION.md contracts/administrator-trial-v2.schema.json fixtures/administrator-trial-conformance-v2.json examples/trials/policy-simulation-definition.json docs/ADR-010-administrator-trial-evidence-is-non-authorizing.md docs/ADMINISTRATOR_TRIAL_WORKFLOW.md; do
  grep -Eq "/${required}$" "$listing" || fail "package is missing $required"
done

source_root="$cleanup_dir/source"
mkdir -p "$source_root"
tar -xzf "$crate" -C "$source_root"
source_dir="$source_root/iicp-management-core-$version"
install_root="$cleanup_dir/install"
exercise_trial() {
  local binary="$1" prefix="$2"
  local definition="$source_dir/examples/trials/policy-simulation-definition.json"
  local session="$cleanup_dir/$prefix-session.json" event="$cleanup_dir/$prefix-event.json"
  local outcome="$cleanup_dir/$prefix-outcome.json" evidence="$cleanup_dir/$prefix-evidence.json"
  local summary="$cleanup_dir/$prefix-summary.json"
  "$binary" trial start "$definition" --output "$session" >/dev/null
  python3 - "$session" "$event" "$outcome" <<'PY'
import json,sys
session=json.load(open(sys.argv[1],encoding="utf-8")); now=session["started_at"]
json.dump({"schema_version":"iicp.management-administrator-trial-event.v2","event_id":"event:package:1","occurred_at":now,"kind":"interaction","phase_code":"policy_preview"},open(sys.argv[2],"w",encoding="utf-8"))
json.dump({"schema_version":"iicp.management-administrator-trial-outcome.v2","completed_at":now,"outcome":"success","machine_result_digest":"sha256:"+"a"*64,"canonical_test_references":["test:package:receipt"]},open(sys.argv[3],"w",encoding="utf-8"))
PY
  "$binary" trial event "$session" "$event" >/dev/null
  "$binary" trial finish "$session" "$outcome" --output "$evidence" >/dev/null
  "$binary" trial verify "$evidence" >/dev/null
  "$binary" trial summarize "$evidence" --output "$summary" >/dev/null
  python3 - "$evidence" "$summary" <<'PY'
import json,sys
evidence=json.load(open(sys.argv[1],encoding="utf-8")); summary=json.load(open(sys.argv[2],encoding="utf-8"))
assert evidence["claim_status"] == "observer_declared"
assert evidence["authorizes_mutation"] is False and evidence["release_gate_authorized"] is False
assert summary["numerical_threshold_met"] is False
assert summary["authorizes_mutation"] is False and summary["release_gate_authorized"] is False
PY
}
CARGO_HOME="$cleanup_dir/online-cargo-home" cargo install --locked --path "$source_dir" --root "$install_root"
"$install_root/bin/iicp-management" --json profile verify "$source_dir/examples/finance/management-profile.json" >/dev/null
"$install_root/bin/iicp-management" --json profile intersect "$source_dir/examples/finance/management-profile.json" "$source_dir/examples/finance/management-profile-requirement.json" >/dev/null
"$install_root/bin/iicp-management" --json plan "$source_dir/examples/finance/desired-state.json" "$source_dir/examples/finance/accepted-state.json" >/dev/null
sandbox="$cleanup_dir/sandbox.json"
diagnostic="$cleanup_dir/diagnostic.json"
"$install_root/bin/iicp-management" bootstrap sandbox >"$sandbox"
python3 - "$sandbox" "$diagnostic" <<'PY'
import json,sys
value=json.load(open(sys.argv[1],encoding="utf-8"))
json.dump(value["diagnostic_bundle"],open(sys.argv[2],"w",encoding="utf-8"),indent=2,sort_keys=True)
PY
"$install_root/bin/iicp-management" diagnostics verify "$diagnostic" >/dev/null
"$install_root/bin/iicp-management" diagnostics show "$diagnostic" >/dev/null
authorized="$cleanup_dir/authorized.json"
"$install_root/bin/iicp-management" --json bootstrap sandbox --exercise authorized-local >"$authorized"
python3 - "$authorized" <<'PY'
import json,sys
value=json.load(open(sys.argv[1],encoding="utf-8"))
assert value["lifecycle"]["state"] == "converged"
assert value["evidence_class"] == "project_rehearsal"
assert value["representative"] is False
assert value["activated_external_state"] is False
PY
for scenario in verification-failure interrupted-resume; do
  result="$cleanup_dir/$scenario.json"
  "$install_root/bin/iicp-management" --json bootstrap sandbox --exercise authorized-local --scenario "$scenario" >"$result"
  python3 - "$scenario" "$result" <<'PY'
import json,sys
scenario,value=sys.argv[1],json.load(open(sys.argv[2],encoding="utf-8"))
expected={"verification-failure":"failed","interrupted-resume":"partially_converged"}
assert value["lifecycle"]["state"] == expected[scenario]
assert value["automatic_retry_permitted"] is False
PY
done
"$install_root/bin/iicp-management-conformance" >/dev/null
exercise_trial "$install_root/bin/iicp-management" online
set +e
controller_help="$($install_root/bin/iicp-management-controller 2>&1)"; controller_status=$?
set -e
[[ $controller_status -eq 2 && "$controller_help" == usage:* ]] || fail "controller install smoke failed"

mkdir -p "$source_dir/.cargo"
cargo vendor --locked --manifest-path "$source_dir/Cargo.toml" "$source_dir/.cargo/vendor" >/dev/null
cat >"$source_dir/.cargo/config.toml" <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = ".cargo/vendor"
EOF
offline_install="$cleanup_dir/offline-install"
CARGO_HOME="$cleanup_dir/offline-cargo-home" cargo install --offline --locked --path "$source_dir" --root "$offline_install"
"$offline_install/bin/iicp-management-conformance" >/dev/null
"$offline_install/bin/iicp-management" --json bootstrap sandbox --exercise authorized-local >/dev/null
exercise_trial "$offline_install/bin/iicp-management" offline

mkdir -p "$OUTPUT"
offline="$OUTPUT/iicp-management-core-$version-offline.tar.gz"
tar -czf "$offline" -C "$source_root" "iicp-management-core-$version"
cp "$crate" "$OUTPUT/"
python3 scripts/generate_release_manifest.py --root "$ROOT" --crate "$OUTPUT/$(basename "$crate")" --offline-bundle "$offline" --commit "$head" --output "$OUTPUT/release-manifest.json"
printf 'release readiness passed\nmanifest: %s\n' "$OUTPUT/release-manifest.json"
