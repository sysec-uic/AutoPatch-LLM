# Contributing Guidelines: How to Collaborate and Improve This Project  

👋 Hi there!  

We're thrilled that you'd like to contribute to this project. Your help is essential for keeping it great. Please take a moment to review these guidelines to ensure a smooth contribution process.  

## Submitting a Pull Request  

We use [pull requests](https://github.com/sysec-uic/AutoPatch-LLM/pulls) to contribute new features, fixes, or documentation.  

### **Steps to Submit a Pull Request**  

1. **Keep Changes Focused**  
   - If making multiple changes that are not dependent on each other, submit them as separate pull requests.  
   - Keep PRs as small and focused as possible to make the review process easier.  

2. **Write Descriptive Commit Messages**  
   - Clearly describe the changes in each commit.  
   - Follow a structured format where possible

3. **Draft Pull Requests**  
   - Draft PRs are welcome if you need early feedback or are blocked by an issue.  

### **Keeping Your Branch Up to Date**  
Before creating a pull request, ensure your branch is up to date with `main`:  

- git pull origin main

# Code Quality

All code must follow these standards before submission:

## Run the formatter:

```bash
black .
isort .
```

## Ensure linting passes:

```bash
flake8
```

## Run tests (if applicable) and verify no regressions:
```
pytest
```

## Making a Pull Request
- Ensure your branch is up to date with main.
```
git pull origin main
```
- Run all tests and fix any issues.
- Submit a pull request with a clear title and description.
- Address any feedback from reviewers.

By following these guidelines, you help maintain a clean and efficient codebase. Happy coding!
