# Contributing

Welcome. This project is under active development and the branching model
is strict for a reason — read this whole file before opening a PR.

## Golden path

```
feat/<your-work>  ──► PR ──►  dev  ──► (PM merges) ──►  main
```

- Feature branches are cut from **`dev`**, never from `main`.
- PRs target **`dev`**, never `main`.
- Only the PM promotes `dev → main`, and only when CI is green on `dev`.
- `main` is production truth. Nothing lands on it except through `dev`.

## Day-to-day

```bash
# Start new work
git checkout dev
git pull origin dev
git checkout -b feat/my-thing

# Keep the branch fresh (pull from dev, NEVER from main)
git fetch origin
git merge origin/dev          # or: git rebase origin/dev

# Ship it
git push -u origin feat/my-thing
gh pr create --base dev       # target is ALWAYS dev
```

If you realize your feature branch was cut from `main` by mistake:

```bash
git rebase --onto origin/dev $(git merge-base HEAD origin/main) HEAD
```

Then flag it in the team channel so the PM can double-check.

## Hard rules

- Never push to `main`.
- Never merge a feat branch into `main`.
- Never open a PR with `--base main`.
- Never pull from `main` into a feat branch.
- Never skip hooks (`--no-verify`) or bypass signing without a written
  exception in the PR description.

The rule exists because ignoring it in April 2026 cost us a 22-commit
divergence and several hours of reconciliation. See `CLAUDE.md` for the
full incident write-up.

## PR checklist

Every PR should:

- Target `dev`.
- Pass `make lint`, `make test-unit`, and relevant integration tests.
- Update `CLAUDE.md` if it changes a convention, key file, or workflow.
- Update `docs/MODEL_JOURNAL.md` if it changes model behavior.
- Include a one-paragraph "why" in the description.

A PR template will pre-populate this checklist when you run
`gh pr create`.

## Claude Code and other AI pair programmers

Claude Code sessions can suggest whatever looks locally convenient —
**including things that violate the rules above**. If your session
proposes any of the following, stop it and redirect:

- `git push origin main` or `git push -f origin main`
- `gh pr create --base main` from a feat branch
- `git checkout -b feat/... main` (branching off main)
- `git merge origin/main` into your feat branch

When in doubt, read `CLAUDE.md` and this file. They are the source of
truth. The agent's summary of "what it intended to do" is not.

## Questions

Open a discussion in the team channel or file an issue tagged `question`.
