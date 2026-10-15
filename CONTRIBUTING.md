# Contributing to omclip

Thank you for your interest in contributing to `omclip`!

## Guidelines

1. **Python Compatibility**: Python 3.11+ standard library. No third-party packages in site-packages (except optional system bindings like PyGObject / python-dbus when available).
2. **Testing**: Run the unit test suite locally before submitting changes:
   ```bash
   python3 -m unittest discover -s tests
   ```
   All tests must pass. Add new unit tests in `tests/` for any new functionality or bug fixes.
3. **Code Style**:
   - Keep code clean, modular, and maintainable.
   - Follow existing patterns in `lib/omclip/`.
   - Avoid unnecessary allocations and dependencies.
4. **Pull Requests**:
   - Open a pull request against `master`.
   - Ensure CI passes successfully.
