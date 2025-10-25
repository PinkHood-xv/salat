# Contributing to SALAT v2

Thank you for your interest in contributing to SALAT v2! This document provides guidelines for contributing to the project.

## Code of Conduct

Be respectful, professional, and constructive in all interactions with the project community.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- Clear, descriptive title
- Detailed steps to reproduce the problem
- Expected behavior vs actual behavior
- Log samples (sanitized of sensitive data)
- Your environment (OS, Python version, dependencies)
- Screenshots or command output if relevant

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- Clear description of the enhancement
- Use cases and benefits
- Potential implementation approach
- Any drawbacks or limitations to consider

### Pull Requests

1. **Fork and Clone**
   ```bash
   git clone https://github.com/yourusername/salat.git
   cd salat/salat_v2
   ```

2. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**
   - Follow the coding style guidelines below
   - Add tests if applicable
   - Update documentation as needed

4. **Test Your Changes**
   ```bash
   # Test with sample logs
   ./salat sample_logs/auth_sample.json

   # Run any existing tests
   python -m pytest tests/
   ```

5. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "Add feature: brief description"
   ```

6. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```
   Then create a Pull Request on GitHub.

## Coding Guidelines

### Python Style

- Follow PEP 8 style guide
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters
- Use meaningful variable and function names

### Code Structure

- Keep functions focused and single-purpose
- Add docstrings to functions and classes
- Include type hints where appropriate
- Handle errors gracefully with informative messages

### Example Function

```python
def parse_log_entry(entry: dict) -> dict:
    """
    Parse a log entry and normalize its format.

    Args:
        entry: Raw log entry dictionary

    Returns:
        Normalized log entry with standard fields

    Raises:
        ValueError: If entry is missing required fields
    """
    # Implementation here
    pass
```

## Adding New Features

### New Detectors

1. Create a new file in `detectors/` directory
2. Inherit from `BaseDetector` class
3. Implement required methods:
   ```python
   from detectors.base import BaseDetector

   class MyDetector(BaseDetector):
       def detect(self, events):
           # Implementation
           pass
   ```
4. Register in `lib/detectors.py`
5. Add tests and documentation

### New Parsers

1. Create parser in `parsers/` directory
2. Implement parsing function:
   ```python
   def parse_myformat(file_path):
       # Parse and return list of normalized events
       pass
   ```
3. Add format detection in `lib/parser.py`
4. Test with sample logs

### New Output Formats

1. Create formatter in `formatters/` directory
2. Implement formatting function:
   ```python
   def format_myformat(events, detections):
       # Format and return output
       pass
   ```
3. Register in `lib/formatters.py`
4. Add to CLI options

## Testing

### Manual Testing

Always test your changes with:

```bash
# Basic functionality
./salat sample_logs/auth_sample.json

# With your new feature
./salat --your-option sample_logs/auth_sample.json

# Edge cases
./salat nonexistent_file.log  # Should handle gracefully
./salat --invalid-option file.log  # Should show helpful error
```

### Test Data

- Use sample logs in `sample_logs/` directory
- Create new samples for new features
- Sanitize any real log data before adding

## Documentation

### Update Documentation When:

- Adding new command-line options
- Creating new detectors or parsers
- Changing existing behavior
- Adding dependencies

### Documentation Files to Update:

- `README.md` - Main documentation
- `QUICK_START.md` - If affecting basic usage
- Code comments and docstrings
- Help text in `lib/cli.py`

## Commit Messages

Write clear commit messages:

```
Add port scan detection for ICMP traffic

- Implement ICMP-based port scan detection
- Add tests for ICMP detection
- Update documentation with new detection type
```

## Questions or Need Help?

- Check existing documentation in `README.md`
- Review `IMPLEMENTATION_PLAN.md` for architecture details
- Look at existing code for examples
- Open an issue for questions or clarifications

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Recognition

Contributors will be recognized in the project documentation. Thank you for helping improve SALAT v2!
