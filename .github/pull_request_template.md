## What this PR does

<!-- One paragraph. Why this change, not just what. -->

## Branch hygiene

- [ ] Base branch is `dev`, not `main`
- [ ] Branch was cut from `dev` (not from `main`)
- [ ] CI is green (`make lint`, `make test-unit`, and any relevant integration tests)

## Scope checks

- [ ] Updated `CLAUDE.md` if this PR changes a convention, key file, or workflow
- [ ] Updated `docs/MODEL_JOURNAL.md` if this PR changes model behavior, features, or hyperparameters
- [ ] Added an ADR under `docs/adr/` if this PR makes an architectural decision
- [ ] No new `os.getenv()` outside `src/common/config.py`
- [ ] No new `print()` in `src/` (scripts/ is fine)
- [ ] No re-introduction of blanket `.fillna(0)` in `src/model/features.py`

## Test plan

<!-- How you verified this works. Commands run, outputs observed, edge cases covered. -->

## Notes for reviewer

<!-- Anything you want to flag explicitly — risky areas, open questions, TODOs. -->
