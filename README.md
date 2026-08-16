# jdebug

A zero-dependency, lightweight, standalone interactive process debugger and instruction disassembler for x86-64 and i386 Linux systems.

`jdebug` uses the native Linux `ptrace` API to spawn, trace, single-step, and monitor child execution contexts natively. Unlike traditional custom debuggers, `jdebug` embeds its own decoding table architecture based directly on the Intel Specification Manuals, completely removing the need for heavy third-party disassembler libraries like Capstone.

---

## Key Features

- **Zero Third-Party Dependencies:** Compiles natively into a compact standalone binary via standard GCC pipelines.
- **Bi-Mode Architecture Auto-Detection:** Dynamically inspects the child process Code Segment (`CS`) execution ring context at runtime to switch parsing tables between 64-bit and legacy 32-bit execution layers seamlessly.
- **Interactive Control Loop Console:** Offers an intuitive command line inside the debugger allowing full control on every execution boundary.
- **Software Breakpoint Engine (`b`):** Safely injects `0xCC` (`INT3`) trap instructions into process memory space, handles hardware signaling traps, rewinds `RIP` pointers, and transparently re-arms breakpoints for continuous passes.
- **Runtime Memory & Stack Virtualization (`m` / `s`):** Peeks directly into child virtual memory segments, strings, or active execution call stack pointers (`RSP`) at runtime.
- **Mnemonic Execution Keyword Filters (`f`):** Automated tracing engine shifts into silent fast-forward mode, stepping through code without layout pollution until a specified assembly keyword (e.g., `syscall`, `int 0x80`, `jmp`) is hit.
- **Clean Columnar Layout Disassembly:** Synchronizes instructions alongside raw aligned multi-byte hex dumps and structural operational comments (such as absolute branch destination resolution tracking).

---

## Requirements

- **Operating System:** Linux (Ubuntu/Debian/Fedora/Arch)
- **Architecture:** x86_64 CPU core with 32-bit multilib execution support enabled (to run 32-bit executable targets)
- **Assembler Tools:** `fasm` (Flat Assembler) to compile target test binaries
- **Compiler tools:** `gcc`, `make`

---

## Installation & Compilation

Clone the repository and build the binary via the integrated `Makefile`:

```bash
git clone https://github.com/jogijas/jdebug.git
cd jdebug
make
```

To clean build configurations or remove binary footprints:
```bash
make clean
```

---

## Interactive Command Map

When `jdebug` pauses at an instruction boundary, you can pass the following console directives:

| Command | Arguments | Description | Example |
| :--- | :--- | :--- | :--- |
| **Enter / n** | None | Single-step execution forward by exactly one instruction. | `jdebug> n` |
| **c** | None | Continuous execution until a breakpoint is tripped or process exits. | `jdebug> c` |
| **b** | `<hex_address>` | Inject a software breakpoint into the target memory segment. | `jdebug> b 4000be` |
| **m** | `<hex_address> <words>` | Hex-dump a specific virtual memory pointer segment location. | `jdebug> m 80490bf 4` |
| **s** | None | Convenience shorthand to inspect the top 4 quadwords of the stack pointer. | `jdebug> s` |
| **f** | `<mnemonic_string>` | Fast-forward single-stepping silently until a token string matches. | `jdebug> f syscall` |

---

## Usage Guide & Real-World Examples

### 1. Basic Step Debugging
Launch a compiled binary under the tracing harness:
```bash
./jdebug ./your_target_program
```

### 2. Setting Breakpoints and Continuing
```text
RIP: 4000b0 -> Machine Code: 49 c7 c0 01 00 00 00           mov     r8, 0x1
-------------------------------------------------------------------------------------------
Commands: [Enter/n] Step, [c] Continue, [b <hex_addr>] Break, [m <hex_addr> <words>] Mem, [s] Stack, [f <str>] Filter
jdebug> b 4000d3
[*] Breakpoint 0 set successfully at target: 0x4000d3
jdebug> c

*** Breakpoint 0 hit at address: 0x4000d3 ***
-------------------------------------------------------------------------------------------
RIP: 4000d3 -> Machine Code: ba 14 00 00 00                 mov     edx, 0x14
-------------------------------------------------------------------------------------------
```

### 3. Automated System Call Interception
Skip tracking standard computational registry loops and jump straight to the next active hardware system call boundary:
```text
jdebug> f syscall
[*] Fast-forwarding tracing context until mnemonic matches: 'syscall'

[Filter Target Matched: 'syscall']
-------------------------------------------------------------------------------------------
RIP: 4000e9 -> Machine Code: 0f 05                          syscall
-------------------------------------------------------------------------------------------
```

### 4. Assembling and Running the FASM Test Suite
The repository includes dedicated x86-64 and i386 test files under the `tests/` directory to validate multi-mode decoding constraints.

**Compile the 64-bit Test Stub:**
```bash
fasm tests/hello64.asm tests/hello64
./jdebug tests/hello64
```

**Compile the 32-bit Compatibility Mode Test Stub:**
```bash
fasm tests/write.asm tests/write
./jdebug tests/write
```

---

## Project Structure Details

- `src/jdebug.c`: Main entry point containing structural parsing functions (`decode_intel_format`), register width converters (`get_reg_name`), pointer formatting, and the `ptrace` execution matrix state machine loop.
- `scripts/strip_comments.sh`: A helper utility to clean up multi-line code files without damaging valid embed literal tokens via localized Perl evaluation wrappers.
- `tests/hello64.asm`: Flat Assembler test program targeting pure 64-bit CPU structures.
- `tests/write.asm`: Flat Assembler test program targeting legacy 32-bit mode system interrupts (`int 0x80`).

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.
