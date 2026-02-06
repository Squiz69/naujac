# Contributing Guidelines

Thank you for your interest in contributing to the Fileless Reflective DLL Loader project!

## Important Notice

This is an **educational security research project**. All contributions must:
- Enhance educational value
- Improve code quality and security
- Add safety features
- Improve documentation
- **Never** facilitate or encourage malicious use

## Code of Conduct

### We Encourage
✅ Educational improvements  
✅ Security enhancements  
✅ Better documentation  
✅ Bug fixes  
✅ Performance improvements  
✅ Additional safety checks  
✅ Detection avoidance research (for defensive understanding)

### We Prohibit
❌ Features specifically designed for malicious use  
❌ Removal of safety warnings  
❌ Obfuscation intended to hide malicious behavior  
❌ Features that harm users or systems  
❌ Contributions that violate laws or ethical guidelines

## How to Contribute

### 1. Fork and Clone
```bash
git clone https://github.com/yourusername/naujac.git
cd naujac
```

### 2. Create a Branch
```bash
git checkout -b feature/your-feature-name
```

### 3. Make Your Changes

Follow the project's coding style:
- Use consistent indentation (4 spaces)
- Add comments for complex logic
- Follow C++17 standards
- Use descriptive variable names
- Keep functions focused and small

### 4. Test Your Changes
```bash
# Build the project
./build.sh  # or build.bat on Windows

# Test in a VM
# Verify no regressions
# Document test results
```

### 5. Commit Your Changes
```bash
git add .
git commit -m "feat: Add descriptive commit message"
```

Use conventional commit messages:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Test additions
- `chore:` - Maintenance tasks

### 6. Submit a Pull Request

Include in your PR:
- Clear description of changes
- Motivation for the change
- Test results
- Documentation updates
- Confirmation of ethical use

## Coding Standards

### C++ Style Guide

```cpp
// Good: Clear, documented, safe
/**
 * @brief Validates PE headers before mapping
 * @param buffer Raw PE file buffer
 * @return true if valid, false otherwise
 */
bool ValidatePE(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) {
        std::cerr << "[!] Buffer too small" << std::endl;
        return false;
    }
    // ... validation logic
    return true;
}

// Bad: Unclear, undocumented, unsafe
bool v(const std::vector<uint8_t>& b) {
    auto h = (IMAGE_DOS_HEADER*)b.data();
    return h->e_magic == IMAGE_DOS_SIGNATURE;
}
```

### Error Handling

Always handle errors gracefully:
```cpp
// Good
if (!result) {
    std::cerr << "[!] Operation failed: " << GetLastError() << std::endl;
    // Clean up resources
    return false;
}

// Bad
if (!result) {
    // Silent failure
    return false;
}
```

### Resource Management

Clean up properly:
```cpp
// Good
HANDLE hProcess = OpenProcess(...);
if (hProcess) {
    // Use handle
    CloseHandle(hProcess);
}

// Better - Use RAII
class ProcessHandle {
    HANDLE handle;
public:
    ProcessHandle(HANDLE h) : handle(h) {}
    ~ProcessHandle() { if (handle) CloseHandle(handle); }
};
```

## Documentation Standards

### Code Comments

```cpp
// Document WHY, not WHAT
// Good
// Suspend thread to prevent race conditions during context modification
SuspendThread(hThread);

// Bad
// Call SuspendThread
SuspendThread(hThread);
```

### README Updates

When adding features:
1. Update README.md with usage examples
2. Add to ARCHITECTURE.md if architecture changes
3. Update SECURITY.md with security implications
4. Update QUICKSTART.md with simple examples

## Testing Guidelines

### Before Submitting

- [ ] Code compiles without warnings
- [ ] All existing functionality still works
- [ ] New features are tested in a VM
- [ ] No memory leaks (use tools like valgrind)
- [ ] Documentation is updated
- [ ] Examples are provided

### Test Environments

Always test in:
- Virtual machine (required)
- Different Windows versions (if possible)
- Both Debug and Release builds

### Test Cases

Example test case documentation:
```
Test: Thread hijacking of notepad.exe
Setup: 
  - Windows 10 x64 VM
  - Notepad.exe running
  - FilelessDLLLoader.exe with ExamplePayload.dll
Expected: 
  - Successful injection
  - Message box displayed
  - No crashes
Result: PASS
```

## Security Considerations

### Security Review Checklist

- [ ] No hardcoded credentials or secrets
- [ ] Input validation for all user inputs
- [ ] Proper error handling
- [ ] No buffer overflows
- [ ] Memory is properly cleaned up
- [ ] Warnings about ethical use are prominent

### Responsible Disclosure

If you discover a security issue:
1. **Do NOT** open a public issue
2. Email the maintainers privately
3. Provide details and reproduction steps
4. Wait for acknowledgment
5. Allow time for a fix before public disclosure

## Project Structure

```
naujac/
├── include/          # Header files
│   ├── NetworkStream.h
│   ├── PEMapper.h
│   ├── ThreadHijacker.h
│   └── PanicFunction.h
├── src/              # Implementation files
│   ├── NetworkStream.cpp
│   ├── PEMapper.cpp
│   ├── ThreadHijacker.cpp
│   ├── PanicFunction.cpp
│   └── main.cpp
├── examples/         # Example payloads
│   └── ExamplePayload.cpp
├── docs/             # Additional documentation
├── tests/            # Test files (future)
├── CMakeLists.txt    # Build configuration
├── README.md         # Main documentation
├── ARCHITECTURE.md   # Technical details
├── SECURITY.md       # Security analysis
├── QUICKSTART.md     # Quick start guide
└── CONTRIBUTING.md   # This file
```

## Areas for Contribution

### High Priority
- x86 (32-bit) support
- Better error messages
- More example payloads (benign)
- Improved documentation
- Cross-platform build support
- Additional safety checks

### Medium Priority
- TLS (Thread Local Storage) support
- Exception handling setup
- Better memory protection handling
- Performance optimizations
- Additional anti-crash safeguards

### Low Priority
- GUI interface (with strong warnings)
- Configuration file support
- Logging improvements
- Additional evasion techniques (educational)

### Documentation Needs
- Video tutorials
- Step-by-step guides
- Architecture diagrams
- More code examples
- Translations (non-English)

## Review Process

### What Happens After Submission

1. **Automated Checks**: Code style, build verification
2. **Manual Review**: Code quality, security implications
3. **Testing**: Functionality and safety testing
4. **Discussion**: Questions and feedback
5. **Approval**: Merge or request changes

### Review Criteria

Reviewers will check:
- Code quality and style
- Security implications
- Ethical considerations
- Documentation completeness
- Test coverage
- Educational value

## Legal Considerations

By contributing, you:
- Grant license to use your contribution
- Confirm you have rights to contribute the code
- Agree the code will be used for educational purposes
- Accept responsibility for ethical use of your contributions

## Questions?

- Open an issue for questions
- Tag it as "question"
- Be specific and provide context

## Acknowledgments

Contributors will be acknowledged in:
- README.md Contributors section
- Git commit history
- Release notes

Thank you for helping make this project better for educational purposes!

---

**Remember**: This project is for education and authorized security research only.
Contributions must uphold the highest ethical standards.
