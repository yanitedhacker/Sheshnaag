# Contributing to CVE Threat Radar

First off, thank you for considering contributing to CVE Threat Radar! It's people like you that make this project better for everyone.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Please be kind and courteous to others.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples** (code snippets, configuration)
- **Describe the behavior you observed and what you expected**
- **Include your environment details** (OS, Python version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description of the proposed enhancement**
- **Explain why this enhancement would be useful**
- **List any alternative solutions you've considered**

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow the coding style** of the project
3. **Add tests** for any new functionality
4. **Ensure all tests pass** before submitting
5. **Update documentation** as needed
6. **Write a clear PR description** explaining your changes

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/cve-threat-radar.git
cd cve-threat-radar

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest -m unit -v
```

## Coding Standards

### Python Style

- Follow [PEP 8](https://pep8.org/) style guidelines
- Use type hints for function arguments and return values
- Write docstrings for all public functions and classes
- Keep functions focused and under 50 lines when possible

### Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters
- Reference issues and pull requests when relevant

Example:
```
Add CVE severity filtering to search endpoint

- Add min_severity and max_severity query parameters
- Update CVEService.search_cves() to handle new filters
- Add unit tests for severity filtering

Closes #123
```

### Testing

- Write unit tests for all new functionality
- Maintain or improve code coverage
- Use descriptive test names that explain what's being tested
- Mark tests appropriately (`@pytest.mark.unit` or `@pytest.mark.integration`)

## Project Structure

```
app/
├── api/routes/      # API endpoint handlers
├── core/            # Core utilities (config, db, security)
├── ingestion/       # Feed ingestion clients
├── ml/              # Machine learning models
├── models/          # Database models
├── patch_optimizer/ # Patch prioritization
├── patch_scheduler/ # Scheduling logic
└── services/        # Business logic
```

## Questions?

Feel free to open an issue with your question or reach out to the maintainers.

Thank you for contributing!
