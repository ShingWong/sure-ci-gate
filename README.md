# sure-ci-gate

The **single, reusable security gate** for the sure-stack projects.

## Design

- **Public (this repo):** the scanner and the reusable CI workflow. Only
  *structural* rules live here — private-key blocks, token shapes, credentials,
  PII shapes, IP addresses, internal path forms and card numbers. Publishing
  these rules discloses nothing project-specific.
- **Private (`ShingWong/sure-master`):** `security/denylist.txt`, the explicit
  terms to reject (product names, internal hosts and IPs, account names,
  customer identifiers). These are fetched at CI runtime with a token and are
  never written into this repository or into a caller's logs.

A leak is therefore caught in two layers: generic structure here, and the
private term list supplied by the caller's CI. Neither layer alone needs to know
the other's content.

## Using the gate

In a workflow such as `.github/workflows/ci-gate.yml` (the filename is up to the caller):

```yaml
name: Security gate
on: [push, pull_request, workflow_dispatch]
permissions:
  contents: read
jobs:
  gate:
    uses: ShingWong/sure-ci-gate/.github/workflows/security-gate.yml@<PINNED_SHA>
    with:
      gate-ref: <PINNED_SHA>
    secrets:
      denylist-token: ${{ secrets.SURE_SECURITY_TOKEN }}
```

Pin **both** the reusable workflow and `gate-ref` to the same commit SHA. Set
`SURE_SECURITY_TOKEN` in the calling repo to a token that can read the private
denylist. Without it the structural scan still runs, with a warning.

## Local use

```bash
node scripts/security-check.mjs
SUN_DENYLIST=/path/to/private-terms.txt SURE_SCAN_ROOT=/path/to/project \
  node scripts/security-check.mjs
```

`SUN_DENYLIST` is a plain text file, one literal per line (`#` comments
ignored). `SURE_SCAN_ROOT` points at the repository to scan; by default the
script scans the repo it lives in.

## License

SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Commercial — Project lextelligent.
