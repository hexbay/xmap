# Contributing to XMap

Thank you for your interest in contributing to XMap! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs

- Before submitting a bug report, please check the existing issues to avoid duplicates
- Use the bug report template when creating an issue
- Include detailed steps to reproduce the bug
- Include any relevant logs or screenshots

### Suggesting Enhancements

- Use the feature request template when creating an issue
- Clearly describe the enhancement and the problem it solves
- Provide examples of how the enhancement would work

### Pull Requests

1. Fork the repository
2. Create a new branch for your feature or bugfix (`git checkout -b feature/your-feature-name`)
3. Make your changes
4. Run tests to ensure your changes don't break existing functionality
5. Commit your changes with clear commit messages
6. Push to your branch (`git push origin feature/your-feature-name`)
7. Open a pull request against the main branch

## Development Setup

1. Ensure you have Go 1.21 or later installed
2. Clone the repository: `git clone https://github.com/hexbay/xmap.git`
3. Install dependencies: `go mod download`
4. Build the project: `go build -o xmap main.go`

## Coding Standards

- Follow standard Go coding conventions
- Use `gofmt` to format your code
- Write clear comments and documentation
- Include tests for new functionality

## Testing

- Run existing tests before submitting a PR: `go test ./...`
- Add new tests for new functionality
- Ensure all tests pass before submitting a PR

## Documentation

- Update documentation for any changes to public APIs
- Keep the README.md up to date
- Document new features or changes in behavior

Thank you for contributing to XMap!
