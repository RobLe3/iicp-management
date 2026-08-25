# Security policy

Please report suspected vulnerabilities privately through GitHub Security
Advisories for this repository. Do not include credentials, private keys,
production configuration or task content in a public issue.

This repository currently provides contracts, a deterministic core and
conformance fixtures. It does not provide a production controller or remote
administration service. Security claims must remain limited to behavior covered
by the executable tests and fixtures.

## Preview release trust boundary

The local release-readiness lane checks four distinct layers:

- `Cargo.lock` and `--locked` preserve the dependency graph selected for the
  release;
- the dependency policy and RustSec audit reject known or explicitly denied
  packages and unapproved registries before product compilation;
- the generated manifest binds the packaged crate, offline bundle and public
  management contracts to one reviewed commit;
- packaged and offline installation tests prove that the tested artifacts can
  be installed and run.

These controls improve determinism and detect known dependency risk. They do
not prove that a maintainer account, source release or build host is
uncompromised, and the preview artifacts are not yet signed binaries. The
manifest explicitly grants neither publication nor deployment authority.


## Diagnostic evidence

Diagnostic bundles project only allowlisted states, counts, reason codes and
digests from validated local inputs. They exclude raw policy and desired-state
content, request and target identifiers, prompts, responses and credentials.
The bundle digest detects modification but does not authenticate the creator.
Operators should still review a bundle before moving it outside its domain
because timing, versions and aggregate operational state may be sensitive.
