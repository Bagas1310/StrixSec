# StrixSec Documentation Index

Welcome to the documentation for **StrixSec**, an Open-Source Cybersecurity Assessment Toolkit.

## Architecture

StrixSec is structured into the following core subsystems:

- **CLI (`strixsec.cli`)**: Terminal user interface powered by Typer and Rich.
- **Core (`strixsec.core`)**: Configuration validation via Pydantic v2, structured logging, and custom exception handling.
- **Scope (`strixsec.scope`)**: Scope parsing, target validation, and inclusion/exclusion boundary enforcement.
- **Recon (`strixsec.recon`)**: Passive and active reconnaissance modules.
- **Assessment (`strixsec.assessment`)**: Security evaluation engines.
- **Findings (`strixsec.findings`)**: Standardized vulnerability finding models and severity classifications.
- **Storage (`strixsec.storage`)**: Result persistence and database backends.
- **Reporting (`strixsec.reporting`)**: Export report generators (HTML, JSON, Markdown).
- **Safety (`strixsec.safety`)**: Authorization checks and safety guardrails.
- **Utils (`strixsec.utils`)**: Shared utility functions and network helpers.
