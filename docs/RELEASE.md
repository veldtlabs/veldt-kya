# veldt-kya — Release Process

Automated publish workflow. Tags trigger the build + publish path.
RC tags publish to TestPyPI; GA tags publish to real PyPI.

## One-time setup (PyPI side — do once per project)

These steps must be done in the PyPI / TestPyPI web UI; the CLI side
of this repo is already wired.

### 1. Reserve the package name on TestPyPI + PyPI

If `veldt-kya` is unclaimed:

- TestPyPI: register at https://test.pypi.org/account/register/, then
  upload one initial dummy `0.0.1` wheel via `twine upload` to claim
  the name. (Or rely on trusted publishing to create the project on
  first publish — TestPyPI allows this.)
- PyPI: same flow at https://pypi.org/account/register/.

### 2. Configure trusted publishing (OIDC, no tokens)

On both TestPyPI **and** PyPI, go to:

```
https://[test.]pypi.org/manage/account/publishing/
```

Click **"Add a new pending publisher"** (or "Add a new publisher" if
the project already exists) and fill in:

| Field | Value |
|---|---|
| PyPI Project Name | `veldt-kya` |
| Owner | `veldtlabs` |
| Repository name | `veldt-kya` |
| Workflow filename | `publish.yml` |
| Environment name | `testpypi` (on TestPyPI) or `pypi` (on PyPI) |

This trusts the `publish.yml` workflow in this repo to upload as
`veldt-kya` without an API token. The `environment:` block in
`publish.yml` matches what you put here.

### 3. Create the two GH environments

In the GH repo Settings → Environments, create:

- `testpypi` — no required reviewers
- `pypi` — **add a required reviewer** (yourself) so GA publish needs
  a manual approval click before it fires. Belt-and-suspenders against
  an accidental tag.

## Per-release process

### Release Candidate (rc) — publishes to TestPyPI

1. Bump `pyproject.toml` version to the rc: e.g. `version = "0.1.0rc1"`
2. Commit the bump on a feature branch, open a PR, merge to main
3. From a clean checkout of main:
   ```
   git tag v0.1.0rc1
   git push --tags
   ```
4. The `publish.yml` workflow fires, builds wheel + sdist, publishes
   to TestPyPI.
5. Verify the install works against TestPyPI:
   ```
   python -m venv /tmp/rc1
   /tmp/rc1/bin/pip install --index-url https://test.pypi.org/simple/ \
     --extra-index-url https://pypi.org/simple/ \
     veldt-kya==0.1.0rc1
   /tmp/rc1/bin/python -c "import kya; print(kya.__version__)"
   ```
6. Share the rc URL with friendly testers. Soak for 1–2 days minimum.

### GA — publishes to PyPI

1. Bump `pyproject.toml` to the GA version: `version = "0.1.0"`
2. Commit + PR + merge
3. Tag and push:
   ```
   git tag v0.1.0
   git push --tags
   ```
4. The workflow fires. Because the `pypi` environment requires manual
   approval, the job pauses — go to the Actions tab and click "Approve
   and run" on the `publish-pypi` job.
5. Workflow publishes to PyPI.
6. Verify:
   ```
   pip install veldt-kya==0.1.0
   ```

## Version-tag invariants

- `pyproject.toml` `version` must match the tag (minus the leading `v`)
  exactly. The workflow's `Verify tag matches pyproject.toml version`
  step fails fast if not.
- Once a version is published, **never re-tag**. Bump a new version
  (e.g. `0.1.0rc2`, then `0.1.0.post1`, then `0.1.1`) instead.
- Pre-releases (rc) only get installed when pip is told to consider
  them: `pip install --pre veldt-kya` or `pip install veldt-kya==0.1.0rc1`.

## What's gated

| Action | Gate |
|---|---|
| Tag `v*rc*` push → TestPyPI publish | none (auto-fires on tag) |
| Tag `v*` push → PyPI publish | `pypi` environment required reviewer (manual click) |
| Wheel build | always runs first via `needs: build` |
| Tag/version mismatch | workflow fails fast with explicit error |

## Soak-window guidance

Skip-rc-and-go-straight-to-GA is risky. Recommended minimum:

| Severity of release | Recommended soak window |
|---|---|
| First-ever publish (any 0.1.0) | 2–3 days minimum, ideally a week |
| Any 0.x → 1.0 major | 1 week |
| Patch (0.x.y → 0.x.y+1) | 24 hours if no API surface change |
| Hotfix (security/data-loss) | 0 — ship straight to GA, document why in release notes |

Soak doesn't mean "do nothing"; install rc into 2–3 friendly
production-shaped environments and exercise the surfaces that
matter for your users.
