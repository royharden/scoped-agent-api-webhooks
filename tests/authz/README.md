# Development authorization regressions

These are builder-authored, construction-exposed development tests. They are
not independent evaluation, study oracle, held-out scenarios or blind mutants.
They use in-process Flask clients, real fixture SQLite schemas and disposable
generated OAuth protocol handles; no socket/listener/provider is needed.

The Authlib spike fixture explicitly enables the adapter only within its test
settings to exercise real library integration. The default application gate is
also tested and remains false outside the explicitly authorized development
spike. A development pass does not itself authorize permanent runtime activation.

Use only INT's shared project interpreter after ENVIRONMENT-READY.json. Set
PYTHONPATH to this worktree/src and select tests/authz, tests/api, tests/ui. Set
pytest --basetemp to a unique directory under Windows TEMP, outside OneDrive.
Do not use another app's interpreter or install from a DL lane. Actual Python,
Authlib pins, commands, failures and active spike duration go in the private
ROUND2 READY receipt. Python3.13 results cannot establish planned3.12 behavior.

Core M14 needs no real credential/account/key placeholder and incurs USD0.
Development checks do not satisfy independent human or construction-exposed
study admission/evaluation gates. Authlib interoperability with an independent
client, a complete mutation expressibility audit, socket/timing/cancellation and
full API/CLI/UI parity require their separately scoped evidence.
