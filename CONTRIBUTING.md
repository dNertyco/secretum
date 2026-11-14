# Contributing

## Workflow

1. Create an issue describing the change (skip for trivial fixes).
2. Branch from `main`: `feat/<short-name>`, `fix/<short-name>`, `chore/<short-name>`, `docs/<short-name>`.
3. Keep pull requests small and focused; fill in the PR template.
4. CI (lint, tests, image build) must be green before merge.
5. Merge with **squash**; the PR title becomes the commit message on `main`. The branch is deleted after merge.

`main` is always releasable. Direct pushes to `main` are not allowed.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>(<scope>): <summary in imperative mood>
```

Types: `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `build`, `ci`, `chore`.
Examples: `feat(storage): add envelope encryption`, `fix(api): return 404 for unknown document`.

## Versioning and releases

[Semantic Versioning](https://semver.org/). Releases are git tags `vMAJOR.MINOR.PATCH`; changes are recorded in
[CHANGELOG.md](CHANGELOG.md) under `Unreleased` and moved to a version section on release.

## Code standards

- `make lint test` passes locally before pushing.
- New behaviour comes with tests; bug fixes come with a regression test.
- Errors are wrapped with context (`fmt.Errorf("load config: %w", err)`); no panics in request paths.
- Never commit secrets, keys or real documents. Use `.env` (ignored) and synthetic test data.
