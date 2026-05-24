# veldt-kya — PyPI Onboarding

**Status:** pre-first-publish · one-time manual steps to enable the
automated rc → soak → GA release pipeline.

**Audience:** the human running the publish for the first time.

**Time:** ~30 minutes of UI clicks across PyPI, TestPyPI, and GitHub.

The automation (`.github/workflows/publish.yml`) is already in this
repo. After the steps below, releases become:

```
bump pyproject.toml version → PR + merge → git tag v0.X.Yrc1 → git push --tags
   ↓
TestPyPI publish fires automatically
   ↓ (soak 1-2 days with friendly testers)
bump pyproject.toml to v0.X.Y → PR + merge → git tag v0.X.Y → git push --tags
   ↓
PyPI publish fires, pauses for your manual approval click
   ↓
Live on PyPI.
```

The release process itself is documented in [`RELEASE.md`](RELEASE.md).
This file is the **one-time** setup needed first.

---

## Prerequisites

- Admin access to the [`veldtlabs/veldt-kya`](https://github.com/veldtlabs/veldt-kya) GitHub repo
- An email address you control (used for both PyPI accounts)
- ~30 minutes uninterrupted

---

## Step 1 — Reserve `veldt-kya` on TestPyPI · 5 min

TestPyPI is the staging environment. Releases publish here first for a
soak window before going live.

1. Open https://test.pypi.org/account/register/
2. Register with the email you control. Choose `veldtlabs` as the
   username if available (matches the GH owner).
3. Confirm the verification email.
4. Enable 2FA at https://test.pypi.org/manage/account/two-factor/ —
   TestPyPI requires 2FA before you can configure trusted publishing.

You do **not** need to upload an initial wheel — trusted publishing
will create the project on first publish.

## Step 2 — Reserve `veldt-kya` on PyPI · 5 min

Same flow, real PyPI:

1. Open https://pypi.org/account/register/
2. Register (use the same email + username if possible for consistency).
3. Confirm verification email.
4. Enable 2FA at https://pypi.org/manage/account/two-factor/ — also
   required for trusted publishing.

## Step 3 — Trusted publisher on TestPyPI · 5 min

This authorizes the GH Actions workflow to publish without an API
token. OIDC handshake means PyPI verifies the request came from the
right repo + workflow at request time.

1. Log into TestPyPI.
2. Go to https://test.pypi.org/manage/account/publishing/
3. Click **"Add a new pending publisher"** (the form is at the bottom
   of the Publishing page).
4. Fill in **exactly**:

   | Field | Value |
   |---|---|
   | PyPI Project Name | `veldt-kya` |
   | Owner | `veldtlabs` |
   | Repository name | `veldt-kya` |
   | Workflow filename | `publish.yml` |
   | Environment name | `testpypi` |

5. Click **Add**.

The "pending" status is normal — it becomes active the first time the
workflow successfully publishes.

## Step 4 — Trusted publisher on PyPI · 5 min

Same as step 3 but on real PyPI:

1. Log into PyPI.
2. Go to https://pypi.org/manage/account/publishing/
3. Click **"Add a new pending publisher"**.
4. Fill in **exactly**:

   | Field | Value |
   |---|---|
   | PyPI Project Name | `veldt-kya` |
   | Owner | `veldtlabs` |
   | Repository name | `veldt-kya` |
   | Workflow filename | `publish.yml` |
   | Environment name | `pypi` |

   *(Note the environment is `pypi`, not `testpypi`. This is the
   only field that differs from step 3.)*

5. Click **Add**.

## Step 5 — Create the two GitHub environments · 5 min

These environments are referenced by the `environment:` block in
`publish.yml` and gate each publish path.

1. Go to https://github.com/veldtlabs/veldt-kya/settings/environments
2. Click **"New environment"** → name it `testpypi` → **Configure environment**.
   - Leave all options at defaults (no required reviewers needed for staging).
   - Click **Save protection rules** if shown.
3. Click **"New environment"** again → name it `pypi` → **Configure environment**.
   - Check **"Required reviewers"**.
   - Add yourself (`veldtlabs`) as a reviewer.
   - Click **Save protection rules**.

The `pypi` reviewer gate means *every* GA publish pauses for a manual
"Approve and run" click in the Actions tab. This is the
belt-and-suspenders against an accidental `git tag v0.1.0` push.

## Step 6 — Sanity-check the configuration · 2 min

1. Open https://github.com/veldtlabs/veldt-kya/settings/environments
   and confirm both `testpypi` and `pypi` exist.
2. Open https://test.pypi.org/manage/account/publishing/ and confirm
   the `veldt-kya` pending publisher row is listed.
3. Open https://pypi.org/manage/account/publishing/ and confirm the
   same row exists there too.
4. Open https://github.com/veldtlabs/veldt-kya/actions/workflows/publish.yml
   to confirm the workflow is visible and ready (it'll show "No runs"
   until you push a tag).

If any of these four checks fails, fix that step before proceeding.

---

## First publish — `0.1.0rc1`

Once steps 1–6 are done, the first release is:

1. **Bump version**:
   ```
   # Edit pyproject.toml — line should read:
   version = "0.1.0rc1"
   ```

2. **Commit on a feature branch + PR + merge** (per the
   feedback_veldt_kya_pr_workflow rule: don't direct-push to main):
   ```
   git checkout -b release/0.1.0rc1
   # edit pyproject.toml
   git add pyproject.toml
   git commit -m "release: bump to 0.1.0rc1"
   git push -u origin release/0.1.0rc1
   gh pr create --base main --title "release: bump to 0.1.0rc1" --body "Pre-release bump for first TestPyPI publish."
   # Wait for CI green, then merge.
   ```

3. **Tag from main**:
   ```
   git checkout main && git pull
   git tag v0.1.0rc1
   git push --tags
   ```

4. **Watch the publish workflow fire**:
   - https://github.com/veldtlabs/veldt-kya/actions/workflows/publish.yml
   - Should take ~2 minutes.
   - On success: https://test.pypi.org/project/veldt-kya/ goes live.

5. **Verify installation** in a fresh venv:
   ```
   python -m venv /tmp/rc1
   /tmp/rc1/bin/pip install --index-url https://test.pypi.org/simple/ \
     --extra-index-url https://pypi.org/simple/ \
     veldt-kya==0.1.0rc1
   /tmp/rc1/bin/python -c "import kya; print(kya.__version__); from kya import score_agent; print(score_agent({'agent_key':'x','tools':['t'],'human_loop':'in_the_loop'}).bucket)"
   ```

   Expected output:
   ```
   0.1.0rc1
   high
   ```

   (Or `medium` / `low` / `critical` — but the import + score call must
   work cleanly.)

6. **Share the rc URL** with 2-3 friendly testers. Soak window:
   - First-ever publish: **2-3 days minimum** before bumping to GA
   - Subsequent patches: 24 hours if no surface change
   - Hotfix: 0 (ship straight to GA, document why)

7. **After soak**, bump to `0.1.0` (no `rc`), PR + merge, tag + push.
   The PyPI publish job pauses for your reviewer approval click.

---

## Troubleshooting

### "Tag does not match pyproject.toml version"

The workflow's verify step fails. Bump `pyproject.toml` to match the
tag (no leading `v`), commit, then tag again. Do **not** retag the
same name — bump the rc instead (`rc2`, `rc3`, ...).

### Trusted publisher 404 / "Unable to authenticate"

Most common cause: a typo in the publisher fields. Re-verify on the
PyPI side that `Workflow filename` is exactly `publish.yml`
(case-sensitive, no path prefix) and the `Environment name` matches
what the workflow declares.

### Forgot to set up the PyPI account before tagging

The workflow will fail at the publish step with an auth error. Stop,
complete the missing onboarding step, then re-run the workflow from
the Actions tab — the wheel build is cached so you don't need to
re-tag.

### Already published `0.1.0rc1` and need to fix something

PyPI does not allow re-uploading the same version. Bump to
`0.1.0rc2` (in pyproject.toml + tag) and re-publish. The yanked
older rc stays on TestPyPI as a record.

### Want to remove a published version

PyPI supports **yanking** (hides from `pip install veldt-kya` but
keeps the file accessible by exact version pin) — go to the project
page on PyPI, find the release, "Yank release". **Deletion** is a
support-ticket process and PyPI's strong preference is yanking
instead.

---

## What this enables

After onboarding:

- Releases are deterministic — every tag = one publish, no manual
  twine commands.
- Pre-releases stay out of `pip install veldt-kya` for users who
  don't pass `--pre`, so testers self-select.
- Tokens never live on disk — OIDC means each publish is a fresh
  short-lived credential issued by GitHub.
- The `pypi` environment's required-reviewer gate means accidental
  tags don't auto-publish.

After GA publish: `pip install veldt-kya` works for anyone.
