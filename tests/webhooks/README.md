# DL3 developer test execution scope

All files in this directory and tests/receivers are construction-exposed builder
DEVELOPMENT regressions. They are not the separate study oracle, independent
verification, held-out data, blind mutations, or product admission evidence.

Partial stdlib environment (ROUND2 r12): use only the exact app-local interpreter
from OUTER run ENVIRONMENT-READY.json, own worktree/src PYTHONPATH and -B:

    python -B -m unittest discover -s tests/webhooks -p stdlib_development.py -v

The explicit pattern excludes pytest modules. The 10-test stdlib suite passed on
Python3.12.13 after correcting an outbox annotation import failure; failed and
passing receipts remain OUTER. Disposable databases use system temp directories.

The pytest, Flask in-process and fake-HTTPX suites are authored but NOT RUN while
dependencies_installed=false. INT alone installs the shared environment and sends
the readiness event. No real network/listener or external model is required by
these tests. The fake-authority fixture is developer-only and proves no OAuth or
authentication gate. Disposable signing material is public test input, not a real
account credential. Placeholder inventory NONE; actual spendUSD0.
