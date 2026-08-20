# Contributing to jdebug

Thank you for your interest in improving `jdebug`! This project is a lightweight, zero-dependency x86-64 and i386 Linux process debugger. Because we avoid third-party libraries, we rely on precise, clean C programming and careful assembly testing.

Please take a moment to review these guidelines before submitting an issue or a pull request.

---

## 🛠️ Local Development Setup

To contribute code changes, you need a local Linux development environment matching the project requirements.

### 1. Install Dependencies
Ensure you have standard C compilation tools and the Flat Assembler (`fasm`) installed to compile the test suite:

```bash
# Ubuntu/Debian example

sudo apt-get update
sudo apt-get install build-essential gcc make fasm gcc-multilib
```

### 2. Fork and Clone
1. Fork the `jdebug` repository on GitHub.
2. Clone your fork locally:

```bash
   git clone https://github.com
   cd jdebug
   ```

### 3. Build the Project
Verify that the project builds natively using the provided `Makefile`:

```bash
make clean && make
```

---

## 🧪 Testing Your Changes

Before submitting a Pull Request, you **must** ensure your changes do not break existing functionality or instruction decoding tables.

### 1. Compile the Test Assembly Suites
Run the Flat Assembler files located in the `tests/` directory:

```bash
# Compile the 64-bit Test Stub
fasm tests/hello64.asm tests/hello64

# Compile the 32-bit Compatibility Mode Test Stub
fasm tests/write.asm tests/write
```

### 2. Run the Debugger
Test both binaries under `jdebug` to verify that `ptrace` control loop limits, software breakpoints, and bi-mode architecture auto-detection work perfectly:

```bash
./jdebug tests/hello64
./jdebug tests/write
```

### 3. Clean Code Requirements
If you add complex macros or operational layout tracking logic, avoid cluttering the repository with dangling inline comments. You can run the included helper utility to sanity-check script formats:

```bash
bash scripts/strip_comments.sh src/jdebug.c
```

---

## 🚀 Pull Request Process

We follow a structured workflow to keep the main branch stable:

1. **Create a Feature Branch:** Always create a descriptive branch off of `main`.

   ```bash
   git checkout -b feature/your-feature-name
   # OR
   git checkout -b fix/bug-description
   ```
2. **Write Clean C Code:** Stick to standard Unix-style formatting, semantic variable naming, and documented struct definitions within `src/jdebug.c`.
3. **Commit with Context:** Make your commit messages short but informative (e.g., `git commit -m "Fix RIP rewind logic on INT3 breakpoint loop"`).
4. **Push and Open a PR:** Push changes to your fork and submit a Pull Request to our `main` branch. Provide a brief summary of what your code changes accomplish and reference any open issues.

---

## 🛑 Code of Conduct

Be respectful, collaborative, and constructive when interacting with other contributors in issues and code reviews. Our goal is to build a fast, secure, and educational tool for low-level systems programming.

---
