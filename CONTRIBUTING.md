# Contributing to StrixSec

Thank you for contributing to StrixSec! Please review the guidelines below before submitting pull requests.

## Code Standards

- **Type Hints**: All function arguments and return types must be explicitly typed.
- **Linting & Formatting**: We enforce strict linting rules with [Ruff](https://github.com/astral-sh/ruff).
  - Run `ruff check .` and `ruff format --check .` before submitting code.
- **Error Handling**: Use custom exceptions defined in `strixsec.core.errors`. Never swallow exceptions silently.
- **Secrets & Credentials**: Never hardcode API keys, credentials, or private target tokens in source code or test fixtures. Use environment variables or configuration files.

## Development Workflow

1. Fork and clone the repository.
2. Setup a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   pip install -e .[dev]
   ```
3. Create a feature branch (`git checkout -b feature/my-feature`).
4. Write code, add unit tests in `tests/unit/`, and verify:
   ```bash
   pytest
   ruff check .
   ```
5. Open a Pull Request with a clear description of your changes.
