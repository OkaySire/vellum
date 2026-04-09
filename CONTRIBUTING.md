# Contributing to Vellum

Thank you for your interest in contributing to Vellum. This document outlines the ground rules for contributing code, documentation, or bug reports.

## Code of Conduct

Be respectful. Discuss ideas, not people. We follow the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Getting Started

### Prerequisites

- .NET SDK 10.0.100 or later (see `global.json`)
- A KEK provider for integration tests (HashiCorp Vault, or use `Vellum.Static` in dev)
- PostgreSQL for `Vellum.EntityFrameworkCore` tests (via Testcontainers)

### Building

```bash
dotnet restore
dotnet build
dotnet test
```

## Ground rules

### 1. No custom cryptography

Vellum does **not** implement cryptographic primitives. We use `System.Security.Cryptography.AesGcm` exclusively. If you believe a new primitive is needed, open an issue first — the answer will likely be "no".

### 2. Fail closed

Any error in key resolution, wrap, or unwrap **must** throw. Never silently return plaintext or skip encryption.

### 3. Provider- and storage-agnostic

Vellum's core does not depend on any specific KEK provider or storage engine. Code in `Vellum.Core` must not reference `Vellum.Vault`, `Vellum.EntityFrameworkCore`, etc.

### 4. C# style

- `TreatWarningsAsErrors = true` — no warnings, ever.
- **Never `var`.** Always explicit types (`string`, `List<T>`, `IKeyEncryptionProvider`, …).
- **Primary constructors** (C# 12+) for classes with DI dependencies.
- **`LoggerMessage` source generators** — no direct `_logger.LogInformation(...)` calls. Use `[LoggerMessage]` attribute on partial classes.
- **`_camelCase`** for private fields; **`PascalCase`** for constants and public members.
- **Sealed by default** — every class `sealed` unless designed for inheritance.
- **Nullable reference types enabled** project-wide.
- **`ConfigureAwait(false)`** on every `await` (this is a library, not an application).
- **One type per file** — file name matches the type name exactly.
- **File-scoped namespaces** — always.

The `.editorconfig` enforces most of these via analyzer diagnostics at build time.

### 5. Tests are mandatory

Every public API change needs tests. Every bug fix needs a regression test. Tests live next to the package they cover under `tests/<PackageName>.Tests/`.

### 6. No secrets in logs

Vellum must never log DEKs, KEKs, nonces, or ciphertexts. Log identifiers (key IDs, scopes) and metadata only.

## Pull requests

1. Fork, branch from `main`, make your changes.
2. Run `dotnet format --verify-no-changes`, `dotnet build`, `dotnet test`.
3. Update `CHANGELOG.md` under `[Unreleased]`.
4. Open a PR with a clear description of the change and its motivation.
5. At least one maintainer review is required. Security-sensitive changes require two.

## Reporting bugs

File bugs via GitHub Issues. For **security vulnerabilities**, follow [SECURITY.md](SECURITY.md) instead — do not open public issues.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
