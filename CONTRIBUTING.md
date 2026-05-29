# Contributing to BitVex

Thank you for your interest in contributing to BitVex. This document outlines the process for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a feature branch from `main`
4. Make your changes
5. Run tests and linting
6. Submit a pull request

## Development Setup

```bash
git clone https://github.com/<your-username>/bitvex.git
cd bitvex
cargo build
cargo test
```

## Code Standards

- All code must pass `cargo clippy` with zero warnings
- All code must be formatted with `cargo fmt`
- New features must include unit tests
- Public APIs must have documentation comments

Before submitting a PR:

```bash
cargo fmt
cargo clippy
cargo test
```

## Pull Request Process

1. Update documentation if your change affects the public API
2. Add tests for new functionality
3. Ensure CI passes
4. Request review from a maintainer

## Reporting Issues

When reporting bugs, please include:

- Rust version (`rustc --version`)
- OS and architecture
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output (run with `-v`)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
