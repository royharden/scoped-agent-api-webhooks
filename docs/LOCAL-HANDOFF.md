# M14 final Dirty handoff — stopped by Roy

Roy directed a local-only handoff/commit and STOP on 2026-10-27/28. **No Docker, installs, tests, new source packages or automatic continuation now.** Fresh Roy relaunch is required when RAM is free. All unstarted grants are revoked. Preserve branches, worktrees, failed logs and temporary development artifacts; do not reset/clean/remove them.

## Delivered and actual evidence

Source baseline before this handoff commit: `2f87298bf9879f32291b96b50c5a0e1a6b4a4098`. `git rev-parse HEAD` after relaunch identifies the handoff commit; do not infer identity from a branch name alone. All owner candidates are integrated locally and there are no remotes.

- Durable work-order store, legal transitions/CAS, current-principal policy, atomic audit/snapshot event insertion, idempotency expiry/tombstones and human-bound approval capability source.
- Separate mock Authlib AS and protected Flask API/human UI source, CSRF/session/request-proof checks, management key forwarding, shared revoke/refresh-reuse cascade, and same-connection worker grant callback. Authlib activation gate remains FALSE.
- Grant-bound subscriptions/outbox/replay/retry/signing/rotation, bounded HTTP delivery adapter and receiver factories; reference inbox-before-ACK/dedupe/version/retention, verify-only and a repository-root insecure comparison excluded from the product namespace.
- CLI/scripted HTTP client, in-memory discovery/S256/callback/refresh/revoke controller and lazy authenticated Session factory, joined fixture composition, original development registry/disposable-consent/in-process public callback adapters. M20 artifacts remain `stub_only`; example deliveries are unsigned/unexecuted.
- Reviewed DEVELOPMENT regressions under `tests/host`, `tests/authz`, `tests/api`, `tests/ui`, `tests/webhooks`, `tests/receivers`, `tests/clients`.

Owners report separate app-local Python **3.12.13** stdlib runs passed: domain **8**, authority **3**, delivery/receivers **10**, clients **6**. Exact commands, candidate provenance and logs are in private run READY packets. These were separate builder development runs, NOT a combined full-product or independent suite. INT separately imported the integrated outbox successfully on 3.12.13.

The first actual delivery unittest discovery FAILED before product tests ran: `DeliveryService.list` shadowed builtin `list` in an eagerly evaluated annotation. DL3 corrected it with postponed annotations; failed discovery and subsequent passing output are preserved. Prior static passes are not retroactively runtime evidence.

All broader pytest/Flask/HTTPX/Authlib tests are **NOT RUN**. The <=60-minute active-runtime Authlib spike **has not started**. No socket/timing/cancellation/installed-wheel/security/independent-study or complete keyless journey pass is claimed. Verdict: **accepted for construction, independence PENDING - Roy**.

## Held work and why

1. Environment: exact app-local CPython3.12.13 was installed. `.venv` and third-party dependencies were not created/installed. The last install guard read **1.158 GiB** free, below the required **>3 GiB**. A stale system `py -3.13` registration points to a missing file; system `python` is 3.11.3. Do not use those or another app's Python. The current stop overrides the earlier Round2 install relaxation.
2. Pins/licensing: `requirements-validation-candidate.txt` contains **unverified candidates**, not a resolved lock. In particular `Authlib==1.9.1` is an inherited planning lead; availability/API compatibility has NOT been verified. Do not silently weaken it or the source `Authlib>=1.9` constraint if unavailable. Resolve exact supported pins and record the P4 disposition first. `standardwebhooks` remains unvendored/declared-only: MIT-metadata vs Apache-2.0-source terms are unresolved; it was not installed. No product/fixture license is publicly adopted.
3. Runtime: run reviewed scoped tests, fix real failures, complete strict Ruff/mypy/property/adversarial checks, verify schema/template wheel data and installed CLI, actual Authlib hook/resource/S256/refresh-reuse interoperability, UI/session/CSRF and API/CLI parity, worker expiry/revoke/crash/cancellation and independent signing verification. No real loopback or Docker journey has run. Source transport declarations are not timing/proxy/redirect behavior proof.
4. Study: source construction preceded any study freeze. Round2 permits a **construction-exposed** study, never pristine pre-code ancestry. No study oracle/scoring/held-out data, declared patch study or >=4 blind patches were authored by this builder team. P2 data/admission, P11 observer/scorer/matrix, P12 mutation study, P14 reproducibility and P15 final independent study remain incomplete. Four distinct fresh outside-builder stand-in sessions still need actual admission (author, non-author reviewer, blind author, runner); INT/DLs/their children are ineligible. Human independence remains PENDING Roy even for delegated stand-ins. Prepared launch packets are not appointments.
5. Demo: original DEVELOPMENT registry and in-process adapters now exist, but successful real Authlib consent/token/refresh/revoke and full durable receiver effects are unverified. Do not present a standalone installed/hosted demo or M20 real integration as ready.

## Exact later local install sequence — DO NOT RUN UNTIL ROY RELAUNCHES

Use a fresh explicitly authorized normal-mode/validation phase. Network remains limited to approved public package installation unless Roy separately authorizes more. No credential files, account creation, live/model calls or paid usage. Run on the intended machine, preserving all current files. Check >3 GiB before EACH interpreter/venv/resolve/install step; stop if lower. The following commands are instructions only and were **not executed during this handoff**.

```powershell
$M14Outer = 'C:\Users\Roy Harden\OneDrive\PJ-OD\PortfolioBuilder\scoped-agent-api-webhooks'
$M14Repo = Join-Path $M14Outer 'scoped-agent-api-webhooks'
$M14Run = Join-Path $M14Outer 'agentops\runs\M14-DIRTY-20261027'
$M14BasePython = Join-Path $M14Outer '.python\cpython-3.12.13-windows-x86_64-none\python.exe'
$M14VenvPython = Join-Path $M14Outer '.venv\Scripts\python.exe'
$M14Cache = Join-Path $M14Outer '.uv-cache'
function Assert-M14Memory {
    $M14FreeGiB = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB / 1GB
    if ($M14FreeGiB -le 3) { throw "M14 RAM guard: $M14FreeGiB GiB; requires >3" }
}
# Only if the already-installed app Python is absent, after checking provenance:
if (-not (Test-Path -LiteralPath $M14BasePython)) {
    Assert-M14Memory
    uv --no-config --cache-dir $M14Cache python install --install-dir (Join-Path $M14Outer '.python') --no-bin --no-registry 3.12.13
    if ($LASTEXITCODE) { throw 'Python install failed; preserve output and stop' }
}
Assert-M14Memory
if (-not (Test-Path -LiteralPath $M14VenvPython)) {
    uv --no-config --cache-dir $M14Cache venv --python $M14BasePython --no-python-downloads (Join-Path $M14Outer '.venv')
    if ($LASTEXITCODE) { throw 'venv creation failed; preserve output and stop' }
}
# FIRST resolve approved, actually available version candidates. No silent fallback.
Assert-M14Memory
uv --no-config --cache-dir $M14Cache pip compile (Join-Path $M14Repo 'requirements-validation-candidate.txt') --python $M14VenvPython --default-index https://pypi.org/simple --only-binary :all: --generate-hashes --output-file (Join-Path $M14Run 'requirements-resolved.txt')
if ($LASTEXITCODE) { throw 'Candidate resolution failed; resolve pins/P4 decision before proceeding' }
Assert-M14Memory
uv --no-config --cache-dir $M14Cache pip install --python $M14VenvPython --default-index https://pypi.org/simple --only-binary :all: --require-hashes --requirement (Join-Path $M14Run 'requirements-resolved.txt')
if ($LASTEXITCODE) { throw 'Dependency installation failed; do not publish ready=true' }
uv --no-config pip freeze --python $M14VenvPython | Set-Content -LiteralPath (Join-Path $M14Run 'installed-packages.txt') -Encoding utf8
& $M14VenvPython --version
```

The binary-only flags avoid building third-party source distributions/install scripts. Retain resolution/install output, wheel/source rights and platform hashes. Inspect/version-pin Authlib's installed API in a <=60-minute bounded spike; don't infer success from install. No library-internals patch or automatic AS rewrite. A failed spike requires an explicit bounded P4b/replan decision. Keep `authlib_spike_approved=False` in ordinary composition until actual evidence supports activation. Do not install the unresolved independent-verifier dependency merely to get a green result.

Only then update the PRIVATE canonical `ENVIRONMENT-READY.json` with actual interpreter, resolved pins/hashes, successful installation, time and scope, and notify newly admitted workers. Old notices/grants are revoked. Do not write ready=true from these instructions or mere file presence.

## Later local execution — fresh authorization and dependencies required

Use a new isolated runtime worktree under the required project directory and temp data outside OneDrive; preserve existing lanes. Run no tests now.

```powershell
$M14ResumeId = [guid]::NewGuid().ToString('N')
$M14RuntimeWT = 'C:\Worktrees\PortfolioBuilder\scoped-agent-api-webhooks\resume-' + $M14ResumeId
$M14PinnedCommit = (git -C $M14Repo rev-parse HEAD).Trim()
git -C $M14Repo worktree add --detach $M14RuntimeWT $M14PinnedCommit
if ($LASTEXITCODE) { throw 'Worktree creation failed; preserve existing paths' }
$env:PYTHONPATH = Join-Path $M14RuntimeWT 'src'
$env:PYTHONDONTWRITEBYTECODE = '1'
Push-Location $M14RuntimeWT
try {
    # First the bounded Authlib spike; preserve output/time/failures.
    & $M14VenvPython -m pytest tests/authz/test_authlib_spike.py -q -p no:cacheprovider --basetemp (Join-Path $env:TEMP ('m14-spike-' + $M14ResumeId))
    # Review the real result before proceeding or changing the gate.
    # Then scoped owner suites / combined integration after concrete fixes:
    & $M14VenvPython -m pytest tests/host tests/authz tests/api tests/ui tests/webhooks tests/receivers tests/clients -q -p no:cacheprovider --basetemp (Join-Path $env:TEMP ('m14-tests-' + $M14ResumeId))
    & $M14VenvPython -m ruff check --select E,F,I,UP,B src tests scripts
    & $M14VenvPython -m mypy --strict src
    & $M14VenvPython -m build --no-isolation --wheel --outdir (Join-Path $M14Run 'wheel')
} finally { Pop-Location }
```

Treat each nonzero/unknown as an actual failure, preserve output and return corrections to its owner. The commands are a sequence to supervise, not a script that turns an earlier failure green by continuing. Strict lint/types/property/concurrency coverage and wheel inclusion have not passed. Inspect the wheel for host/auth SQL and UI templates, and exclusion of evaluation/mutants/root insecure demo; test installed CLI dry-run and actual subprocess parity later. No source label/header establishes actual CLI invocation; retain independent invocation observation. A real loopback/receiver demo needs a fresh scoped runtime/network grant and `agent-ports` claim/check before listeners; no port is reserved by this handoff.

## Conditional later Docker steps — NO DOCKER NOW

Docker is optional, not a prerequisite for the in-process local suites. No Dockerfile/evaluation image/CI scaffolding or image inventory was produced here. After fresh Roy authorization: Kaiser-Pro only, >3 GiB free before EACH Docker step, existing local images only, **no pull/build/download**, no privileged mode, no home-folder/Docker-socket/credential mounts, no stopping Docker/WSL and no touching unrelated containers. Read canonical `skills-bts/agent-ports/SKILL.md` and claim/check the intended instance even without host ports. Existing test image must already contain compatible pinned Python/dependencies; Windows venv wheels cannot be reused as a Linux environment.

```powershell
Assert-M14Memory
docker image ls --no-trunc
# Replace ONLY with a verified already-present local image ID containing the tools.
$M14Image = '<PLACEHOLDER_EXISTING_LOCAL_PY312_IMAGE_ID>'
if ($M14Image.StartsWith('<PLACEHOLDER_')) { throw 'Select/verify a local image; never pull one implicitly' }
Assert-M14Memory
docker image inspect $M14Image
# Verify exact tools/platform in the selected image, no network, then supervised test:
Assert-M14Memory
docker run --pull=never --name ('m14-resume-' + $M14ResumeId) --network none --read-only --tmpfs '/tmp:rw,noexec,nosuid,size=512m' --mount ('type=bind,source=' + $M14RuntimeWT + ',target=/work,readonly') --workdir /work --env PYTHONPATH=/work/src --env PYTHONDONTWRITEBYTECODE=1 --entrypoint python $M14Image -m pytest tests/host tests/authz tests/api tests/ui tests/webhooks tests/receivers tests/clients -q -p no:cacheprovider --basetemp /tmp/m14-tests
```

No `--rm` or volume cleanup: preserve container/output for review. The image placeholder is not a runnable image. If no suitable local image or toolset exists, **stop that Docker path** and request the next phase's concrete remedy; do not pull/build/borrow another app's image or mount credentials. Network-none execution is not a measured loopback journey or reproducibility pass. Capture source/image/lock/environment hashes and actual exit/status before any claim.

## Placeholders, accounts and spend

**Spend: USD 0 of USD 40.** All work was keyless local construction/development. No Roy-supplied account/key is available; no paid usage, buying credits, new accounts, live/model calls or payment method is authorized. Any later paid pilot must use an exact Roy-supplied key/account, log date/amount/purpose/cumulative cost, reconcile a conservative USD35 stop-loss and NEVER exceed USD40. M14 needs no model/API service, so do not introduce one merely because a budget exists.

Active credential/account placeholders: **NONE required by core M14**. `<PLACEHOLDER_SERVICE_API_KEY>` and `<PLACEHOLDER_SERVICE_ACCOUNT_ID>` are documentation-only examples in OUTER `PLACEHOLDERS.md`, not executable inputs; fill only if a separately authorized external test service actually requires a Roy-supplied value. Never invent a secret or read credential/.env/SSH/token files. Disposable synthetic local protocol material is fixture data, not a real external credential.

Every actual missing coordination/runtime placeholder is listed here and in the private inventory:

| Placeholder | Where used | Needed later |
|---|---|---|
| `<PLACEHOLDER_EXISTING_LOCAL_PY312_IMAGE_ID>` | Docker example above | Verified already-present eligible local image ID; no pull |
| `<PLACEHOLDER_EVAL_AUTHOR_SESSION_ID>` | private run `standins/LAUNCH-BINDINGS.json` evaluation-author | Actual fresh outside-builder session |
| `<PLACEHOLDER_EVAL_AUTHOR_MESSAGE_ENDPOINT>` | same binding | Authorized actual console/native endpoint |
| `<PLACEHOLDER_EVAL_REVIEWER_SESSION_ID>` | non-author-reviewer binding | Actual distinct outside-builder session |
| `<PLACEHOLDER_EVAL_REVIEWER_MESSAGE_ENDPOINT>` | same binding | Authorized endpoint |
| `<PLACEHOLDER_BLIND_AUTHOR_SESSION_ID>` | blind-mutant-author binding | Actual fresh scenario-unexposed outside-builder session |
| `<PLACEHOLDER_BLIND_AUTHOR_MESSAGE_ENDPOINT>` | same binding | Authorized endpoint |
| `<PLACEHOLDER_STUDY_RUNNER_SESSION_ID>` | separate-runner binding | Actual distinct outside-builder session |
| `<PLACEHOLDER_STUDY_RUNNER_MESSAGE_ENDPOINT>` | same binding | Authorized endpoint |

Do not fill these with this builder's aliases/children or guessed identities. A placeholder is not an appointment or account authorization. No human-independent claim before Roy names the required humans.

## Open questions for Roy / next integrator

- Fresh relaunch and explicit normal-mode validation scope, restored RAM headroom, permitted loopback/socket/Docker work; this STOP stays effective until then.
- Actual eligible outside-builder stand-in sessions/endpoints and later human-independent author/reviewer/blind-author/runner appointments; preserve >=4 blind patches, construction exposure and no-feedback protocol.
- Exact available compatible Authlib/dependency/spec pins and bounded P4b disposition if the candidate version/spike fails; do not silently replace or weaken scope.
- Product/fixture license decision and pinned independent-verifier license/NOTICE reconciliation. No public license adoption yet.
- Public repo/remotes/push/publish/deploy remain NOT approved. Optional real test accounts/keys only if Roy later supplies a specific need/value; none needed now. No spend beyond USD40 under any circumstances.

## Private resume entrypoints and preservation

OUTER `FINAL-HANDOFF.md` points to this committed guide and private run `agentops/runs/M14-DIRTY-20261027/` (run/roster/append-only status/ledger, exact READY/review/stdout/standdown receipts, environment JSON, placeholder/spend inventories and inert stand-in launch packets). Chat exports remain in the two PRIVATE OUTER `.chatexports` roots, never in this product or worktrees. Paths to transcripts are not permission to read them.

All four DLs acknowledged standdown, report clean preserved branches/worktrees, no owned running services/pollers/containers/children, and verified final exact-session private exports. Future staffing follows Roy's fresh relaunch/admission; old standing grants and environment messages do not restart anyone. No automatic watcher/scheduler was installed.
