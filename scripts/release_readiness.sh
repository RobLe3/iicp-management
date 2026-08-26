#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${IICP_DISPOSABLE_CARGO_ACTIVE:-0}" != 1 ]]; then
  exec "$ROOT/scripts/with_disposable_cargo_target.sh" --label management-release-readiness -- "$0" "$@"
fi
OUTPUT="${1:-$ROOT/release-artifacts/release-readiness}"
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
msrv="$(python3 - <<'PY'
import tomllib
print(tomllib.load(open('Cargo.toml','rb'))['package']['rust-version'])
PY
)"
tag="v$version"
[[ -z "$(git tag --list "$tag")" ]] || fail "tag $tag already exists locally"
if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then fail "tag $tag already exists on origin"; fi
command -v cargo-audit >/dev/null || fail "cargo-audit 0.22.2 is required"
[[ "$(cargo audit --version)" == *"0.22.2"* ]] || fail "cargo-audit 0.22.2 is required"

python3 scripts/check_dependency_policy.py
python3 -m unittest scripts/test_dependency_policy.py scripts/test_release_manifest.py scripts/test_release_readiness.py tools/test_diagnostic_v2_conformance.py
python3 tools/run_diagnostic_v2_conformance.py fixtures/diagnostic-bundle-conformance-v2.json >/dev/null
python3 tools/run_bootstrap_workflow_conformance.py fixtures/bootstrap-workflow-conformance-v1.json >/dev/null
cargo metadata --locked --format-version 1 >/dev/null
command -v rustup >/dev/null || fail "rustup is required to verify declared Rust $msrv"
msrv_cargo="$(rustup which --toolchain "$msrv" cargo 2>/dev/null)" || fail "Rust $msrv toolchain is not installed"
msrv_rustc="$(rustup which --toolchain "$msrv" rustc 2>/dev/null)" || fail "Rust $msrv compiler is not installed"
RUSTC="$msrv_rustc" CARGO_TARGET_DIR="$cleanup_dir/msrv-target" \
  "$msrv_cargo" check --locked --all-targets
advisory="$cleanup_dir/advisory-db"
git clone --quiet --depth 1 https://github.com/RustSec/advisory-db.git "$advisory"
cargo audit --no-fetch --db "$advisory"
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo package --locked

crate="${CARGO_TARGET_DIR:?missing disposable Cargo target}/package/iicp-management-core-$version.crate"
[[ -f "$crate" ]] || fail "packaged crate not found"
listing="$cleanup_dir/package.list"
tar -tzf "$crate" >"$listing"
for required in Cargo.lock Cargo.toml README.md COMPATIBILITY.md CHANGELOG.md CONFORMANCE.md LICENSE "docs/RELEASE_NOTES_$version.md"; do
  grep -Eq "/${required}$" "$listing" || fail "package is missing $required"
done
for required in contracts/management-profile-v1.schema.json fixtures/management-profile-conformance-v1.json examples/finance/management-profile.json docs/ADR-008-single-crate-developer-preview-release.md contracts/diagnostic-bundle-v1.schema.json fixtures/diagnostic-bundle-conformance-v1.json docs/ADR-009-diagnostic-bundles-are-minimized-evidence.md docs/DIAGNOSTIC_BUNDLE_WORKFLOW.md docs/LOCAL_MANAGEMENT_EVALUATION.md contracts/administrator-trial-v2.schema.json fixtures/administrator-trial-conformance-v2.json examples/trials/policy-simulation-definition.json docs/ADR-010-administrator-trial-evidence-is-non-authorizing.md docs/ADMINISTRATOR_TRIAL_WORKFLOW.md contracts/diagnostic-bundle-v2.schema.json fixtures/diagnostic-bundle-conformance-v2.json fixtures/runtime-health-ready-v1.json docs/ADR-013-runtime-aware-diagnostics-preserve-v1.md tools/run_diagnostic_v2_conformance.py contracts/bootstrap-workflow-v1.schema.json fixtures/bootstrap-workflow-conformance-v1.json docs/ADR-014-first-run-preparation-composes-existing-contracts.md tools/run_bootstrap_workflow_conformance.py; do
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
exercise_bootstrap_prepare() {
  local binary="$1" prefix="$2"
  local config="$cleanup_dir/$prefix-runtime-config.json"
  local workflow="$cleanup_dir/$prefix-bootstrap-workflow.json"
  cat >"$config" <<'JSON'
{"schema_version":1,"mode":"local_only","directory":{"source":"local","local_discovery_enabled":false},"membership":{"required":false,"require_authenticated_clients":false,"require_authenticated_nodes":false,"reject_unknown_peers":false},"mesh":{"enabled":false,"require_authenticated_gossip":false},"execution":{"allow_local":true,"allow_external_providers":false,"allow_public_iicp":false},"cip":{"enabled":false,"require_same_trust_domain":false},"federation":{"enabled":false,"trusted_domains":[]},"network":{"allow_public_fallback":false,"allow_external_bootstrap":false,"allow_external_relay":false,"allow_auto_update_network":false},"secret_refs":{}}
JSON
  [[ "$($binary --version)" == "iicp-management $version" ]] || fail "$prefix installed version mismatch"
  "$binary" --json bootstrap prepare "$config" \
    --resource-id runtime:package \
    --operator-id operator:package \
    --controller-id controller:package \
    --controller-generation 0 >"$workflow"
  python3 - "$workflow" <<'PY'
import json,sys
value=json.load(open(sys.argv[1],encoding="utf-8"))
assert value["schema_version"] == "iicp.management-bootstrap-workflow.v1"
assert value["assessment"]["readiness"] == "ready_for_proposal"
assert value["doctor"]["schema_version"] == "iicp.management-doctor-report.v1"
assert value["proposal"]["expected_generation"] == 0
assert value["authorizes_mutation"] is False and value["activated"] is False
PY
}
CARGO_HOME="$cleanup_dir/online-cargo-home" cargo install --locked --path "$source_dir" --root "$install_root"
exercise_bootstrap_prepare "$install_root/bin/iicp-management" online
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
runtime_assessment="$cleanup_dir/runtime-assessment.json"
runtime_diagnostic="$cleanup_dir/runtime-diagnostic.json"
python3 - "$runtime_assessment" <<'PY'
import json,sys,time
now=int(time.time())
json.dump({"schema_version":"iicp.management-bootstrap-assessment.v1","assessment_id":"assessment:packaged-runtime","environment_mode":"local_only","observed_at":now-1,"expires_at":now+300,"readiness":"ready_for_proposal","authorizes_mutation":False,"observations":[],"recommendations":[],"required_decisions":[]},open(sys.argv[1],"w",encoding="utf-8"))
PY
"$install_root/bin/iicp-management" diagnostics create "$runtime_assessment" --runtime-health "$source_dir/fixtures/runtime-health-ready-v1.json" --runtime-target "node:private-package-target" --output "$runtime_diagnostic" >/dev/null
"$install_root/bin/iicp-management" diagnostics verify "$runtime_diagnostic" >/dev/null
"$install_root/bin/iicp-management" diagnostics show "$runtime_diagnostic" >/dev/null
python3 - "$runtime_diagnostic" <<'PY'
import json,sys
value=json.load(open(sys.argv[1],encoding="utf-8")); encoded=json.dumps(value,sort_keys=True)
assert value["schema_version"] == "iicp.management-diagnostic-bundle.v2"
assert len(value["artifacts"]) == 6
assert value["authorizes_mutation"] is False
assert "node:private-package-target" not in encoded and "process_epoch" not in encoded and '"pid"' not in encoded
PY
set +e
"$install_root/bin/iicp-management" diagnostics create "$runtime_assessment" --runtime-health "$source_dir/fixtures/runtime-health-ready-v1.json" --output "$cleanup_dir/partial-runtime.json" >/dev/null 2>&1
partial_runtime_status=$?
set -e
[[ $partial_runtime_status -ne 0 ]] || fail "partial runtime diagnostic flags did not fail closed"
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
"$install_root/bin/iicp-management" completion bash | grep -q "iicp-management __complete"
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
"$offline_install/bin/iicp-management" completion bash | grep -q "iicp-management __complete"
"$offline_install/bin/iicp-management" --json bootstrap sandbox --exercise authorized-local >/dev/null
exercise_bootstrap_prepare "$offline_install/bin/iicp-management" offline
exercise_trial "$offline_install/bin/iicp-management" offline

mkdir -p "$OUTPUT"
offline="$OUTPUT/iicp-management-core-$version-offline.tar.gz"
tar -czf "$offline" -C "$source_root" "iicp-management-core-$version"
cp "$crate" "$OUTPUT/"
python3 scripts/generate_release_manifest.py --root "$ROOT" --crate "$OUTPUT/$(basename "$crate")" --offline-bundle "$offline" --commit "$head" --output "$OUTPUT/release-manifest.json"
IICP_RELEASE_MANIFEST="$OUTPUT/release-manifest.json" \
  cargo test --locked --test release_manifest generated_release_manifest_matches_schema_and_artifact_version -- --exact
printf 'release readiness passed\nmanifest: %s\n' "$OUTPUT/release-manifest.json"
