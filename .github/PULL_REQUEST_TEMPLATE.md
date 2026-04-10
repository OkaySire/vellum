# Pull Request

## Summary

<!-- What does this change do, and why? Link to any issue it closes. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor
- [ ] Documentation
- [ ] CI / build
- [ ] Tests

## Checklist

- [ ] Tests added or updated to cover the change
- [ ] `dotnet build -c Release` succeeds with **zero warnings** (TreatWarningsAsErrors)
- [ ] `dotnet test -c Release` — all tests green on net8.0/net9.0/net10.0
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] XML docs added/updated on public API surface

## Security considerations

<!--
Does this change touch cryptography, key material (DEK/KEK), logging of sensitive
data, or fail-closed paths? If yes, describe what was considered and how the change
preserves the "fail closed, no custom crypto, no secrets in logs" invariants.
If the answer is "no", write "n/a".
-->
