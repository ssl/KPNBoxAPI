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

## Pull Request Process

1. Create a new branch for your feature or bugfix
2. Make your changes
3. Ensure all code quality checks pass
4. Update documentation if needed
5. Submit a pull request with a clear description of your changes

## Code Style

- Follow PEP 8
- Use type hints where possible
- Write docstrings for all public functions and classes
- Keep functions focused and small
- Use meaningful variable and function names

## Testing

Since this library interacts with specific hardware (KPN modems/routers), comprehensive automated testing requires actual hardware that may not be available in all environments. Manual testing with actual KPN devices is encouraged when making changes.

## Reporting Issues

When reporting issues, please include:
- Python version
- KPNBoxAPI version
- Operating system
- KPN modem/router model
- Detailed description of the problem
- Steps to reproduce
- Any error messages

Thank you for contributing! 