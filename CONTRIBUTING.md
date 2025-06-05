# Contributing to KPNBoxAPI

We welcome contributions to KPNBoxAPI! This document provides guidelines for contributing to the project.

## Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/yourusername/KPNBoxAPI.git
   cd KPNBoxAPI
   ```

3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. Install the package in development mode:
   ```bash
   pip install -e ".[dev]"
   ```

## Running Tests

```bash
pytest tests/ -v --cov=src/kpnboxapi
```

## Code Quality

Before submitting a pull request, ensure your code passes all quality checks:

```bash
# Format code
black src/ tests/

# Check formatting
black --check src/ tests/

# Lint code
flake8 src/ tests/

# Type checking
mypy src/
```

## Pull Request Process

1. Create a new branch for your feature or bugfix
2. Make your changes
3. Add or update tests as needed
4. Ensure all tests pass and code quality checks pass
5. Update documentation if needed
6. Submit a pull request with a clear description of your changes

## Code Style

- Follow PEP 8
- Use type hints
- Write docstrings for all public functions and classes
- Keep functions focused and small
- Use meaningful variable and function names

## Reporting Issues

When reporting issues, please include:
- Python version
- KPNBoxAPI version
- Operating system
- Detailed description of the problem
- Steps to reproduce
- Any error messages

Thank you for contributing! 