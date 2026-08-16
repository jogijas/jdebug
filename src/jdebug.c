#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sys/syscall.h>

#define MAX_BPS 16

/* Breakpoint tracking structure */
uint64_t bp_addrs[MAX_BPS];
long bp_orig_data[MAX_BPS];
bool bp_active[MAX_BPS];
int bp_count = 0;

/* Complete instruction metadata parsed straight from Intel architectural manuals */
typedef struct {
    bool is_32bit;      // Flag denoting if target binary runs inside 32-bit mode
    bool has_prefix_66; // 16-bit operand size override
    bool has_prefix_fs; // FS segment override prefix
    bool has_prefix_gs; // GS segment override prefix
    bool has_rex;
    uint8_t rex_w;      // 1 = 64-bit operand size
    uint8_t rex_r;      // Extension to ModR/M 'reg' field
    uint8_t rex_x;      // Extension to SIB 'index' field
    uint8_t rex_b;      // Extension to ModR/M 'r/m' or SIB 'base' field

    uint8_t opcode[3];  // Supports 1, 2, and 3-byte opcodes
    uint8_t opcode_len;

    bool has_modrm;
    uint8_t mod;        // ModR/M addressing mode bits [7:6]
    uint8_t reg;        // ModR/M register selection bits [5:3]
    uint8_t rm;         // ModR/M register or memory lookup bits [2:0]

    bool has_sib;
    uint8_t scale;      // SIB scale multiplier bits [7:6] (1, 2, 4, 8)
    uint8_t index;      // SIB index register selection bits [5:3]
    uint8_t base;       // SIB base register selection bits [2:0]

    int32_t displacement;
    uint8_t disp_len;   // 0, 1, or 4 bytes

    int32_t immediate;
    uint8_t imm_len;    // 0, 1, 2, or 4 bytes

    uint8_t operand_size; // Resolved execution size: 8, 16, 32, or 64 bits
    uint32_t total_len; // Total bytes read for this instruction
} x86_instruction_t;

/* String registers matching standard x86-64 bit widths */
static const char *REG_64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
static const char *REG_32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
static const char *REG_16[] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
static const char *REG_8[]  = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
static const char *REG_8_REX[] = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};

/* Helper to return the correct register name based on architectural width overrides */
static const char *get_reg_name(uint8_t idx, const x86_instruction_t *inst) {
    if (inst->operand_size == 8) {
        return inst->has_rex ? REG_8_REX[idx] : REG_8[idx];
    }
    if (inst->operand_size == 16) return REG_16[idx];
    if (inst->operand_size == 64) return REG_64[idx];
    return REG_32[idx];
}

/* Helper functions to safely extract variable-width data from the stream */
static int16_t read_imm16(const unsigned char *b, uint32_t offset) {
    return (int16_t)(b[offset] | (b[offset + 1] << 8));
}

static int32_t read_imm32(const unsigned char *b, uint32_t offset) {
    return (int32_t)(b[offset] | (b[offset + 1] << 8) | (b[offset + 2] << 16) | (b[offset + 3] << 24));
}

/**
 * @brief Decodes raw variable-width x86 machine code into structured architectural primitives.
 */
uint32_t decode_intel_format(const unsigned char *b, x86_instruction_t *inst, bool is_32bit) {
    uint32_t idx = 0;

    inst->is_32bit = is_32bit;
    inst->has_prefix_66 = false;
    inst->has_prefix_fs = false;
    inst->has_prefix_gs = false;
    inst->has_rex = false;
    inst->rex_w = inst->rex_r = inst->rex_x = inst->rex_b = 0;
    inst->has_modrm = false;
    inst->has_sib = false;
    inst->disp_len = 0;
    inst->imm_len = 0;
    inst->displacement = 0;
    inst->immediate = 0;
    inst->operand_size = 32; // Default execution size

    // 1. Process Legacy Prefixes (0x66 Size Override, 0x64 FS segment, 0x65 GS segment)
    while (b[idx] == 0x66 || b[idx] == 0x64 || b[idx] == 0x65) {
        if (b[idx] == 0x66) {
            inst->has_prefix_66 = true;
            inst->operand_size = 16;
        } else if (b[idx] == 0x64) {
            inst->has_prefix_fs = true;
        } else if (b[idx] == 0x65) {
            inst->has_prefix_gs = true;
        }
        idx++;
    }

    // 2. Process REX Prefixes (0x40 - 0x4F) - STRICTLY DISABLED inside 32-bit execution mode
    if (!is_32bit && b[idx] >= 0x40 && b[idx] <= 0x4f) {
        inst->has_rex = true;
        inst->rex_w = (b[idx] >> 3) & 1;
        inst->rex_r = (b[idx] >> 2) & 1;
        inst->rex_x = (b[idx] >> 1) & 1;
        inst->rex_b = b[idx] & 1;
        if (inst->rex_w) {
            inst->operand_size = 64;
        }
        idx++;
    }

    // 3. Process Multi-byte Opcodes
    inst->opcode[0] = b[idx];
    inst->opcode_len = 1;
    idx++;

    if (inst->opcode[0] == 0x0f) {
        inst->opcode[1] = b[idx];
        inst->opcode_len = 2;
        idx++;
    }

    // 4. Determine if ModR/M is mandatory according to Intel Primary Tables
    uint8_t op = inst->opcode[0];
    bool parse_modrm = false;
/*
    if (inst->opcode_len == 1) {
        if (op == 0x00 || op == 0x30 || op == 0x88 || op == 0x8a ||
            op == 0xc6 || op == 0xf6 || op == 0xd0 || op == 0xd2 || op == 0xc0) {
            inst->operand_size = 8;
            }

            if ((op >= 0x00 && op <= 0x03) || // add
                (op >= 0x30 && op <= 0x33) || // xor
                (op >= 0x88 && op <= 0x8b) || // mov r/m
                (op == 0x8d)               || // lea
                (op == 0x83)               || // immediate extensions
                (op == 0xc6)               || // mov r/m8, imm8
                (op == 0xc7)               || // mov r/m, imm32
                (op == 0xf6) || (op == 0xf7) || // Advanced Arithmetic Group 3
                (op >= 0xd0 && op <= 0xd3) || // Bitwise Shifts Group 2
                (op == 0xc0) || (op == 0xc1))   // Bitwise Immediate Shifts Group 2
            {
                parse_modrm = true;
            }
    }*/
if (inst->opcode_len == 1) {
    if (op == 0x00 || op == 0x30 || op == 0x88 || op == 0x8a ||
        op == 0xc6 || op == 0xf6 || op == 0xd0 || op == 0xd2 || op == 0xc0) {
        inst->operand_size = 8;
        }

        /* Fixed comparison to prevent type-limits compiler warnings */
        if ((op <= 0x03) ||               // add (removed redundant op >= 0x00)
            (op >= 0x30 && op <= 0x33) || // xor
            (op >= 0x88 && op <= 0x8b) || // mov r/m
            (op == 0x8d)               || // lea
            (op == 0x83)               || // immediate extensions
            (op == 0xc6)               || // mov r/m8, imm8
            (op == 0xc7)               || // mov r/m, imm32
            (op == 0xf6) || (op == 0xf7) || // Advanced Arithmetic Group 3
            (op >= 0xd0 && op <= 0xd3) || // Bitwise Shifts Group 2
            (op == 0xc0) || (op == 0xc1))   // Bitwise Immediate Shifts Group 2
        {
            parse_modrm = true;
        }
}


else if (inst->opcode_len == 2) {
        parse_modrm = false;
    }

    if (parse_modrm) {
        inst->has_modrm = true;
        inst->mod = (b[idx] >> 6) & 3;
        inst->reg = (b[idx] >> 3) & 7;
        inst->rm  = b[idx] & 7;
        idx++;

        // 5. Evaluate standard SIB (Scale-Index-Base) structural flags
        if (inst->mod != 3 && inst->rm == 4) {
            inst->has_sib = true;
            inst->scale = (b[idx] >> 6) & 3;
            inst->index = (b[idx] >> 3) & 7;
            inst->base  = b[idx] & 7;
            idx++;
        }

        // 6. Calculate displacement storage offsets
        if (inst->mod == 1) {
            inst->disp_len = 1;
            inst->displacement = (int8_t)b[idx];
            idx++;
        } else if (inst->mod == 2 || (inst->mod == 0 && inst->rm == 5) || (inst->has_sib && inst->mod == 0 && inst->base == 5)) {
            inst->disp_len = 4;
            inst->displacement = read_imm32(b, idx);
            idx += 4;
        }
    }

    inst->total_len = idx;
    return idx;
}

/**
 * @brief Constructs a formatted memory pointer expression using ModR/M and SIB specifications.
 */
void format_memory_operand(const x86_instruction_t *inst, char *buf) {
    char seg_str[8] = "";
    if (inst->has_prefix_fs) sprintf(seg_str, "fs:");
    else if (inst->has_prefix_gs) sprintf(seg_str, "gs:");

    char expr[64];
    uint8_t base_idx = inst->base + (inst->rex_b << 3);
    uint8_t index_idx = inst->index + (inst->rex_x << 3);
    int scale_val = 1 << inst->scale;
    const char **base_table = inst->is_32bit ? REG_32 : REG_64;

    if (inst->has_sib) {
        if (inst->mod == 0 && inst->base == 5) {
            if (index_idx == 4) {
                sprintf(expr, "[0x%x]", inst->displacement);
            } else {
                sprintf(expr, "[%s * %d + 0x%x]", base_table[index_idx], scale_val, inst->displacement);
            }
        } else {
            if (index_idx == 4) {
                if (inst->disp_len == 1 || inst->disp_len == 4)
                    sprintf(expr, "[%s + 0x%x]", base_table[base_idx], inst->displacement);
                else
                    sprintf(expr, "[%s]", base_table[base_idx]);
            } else {
                if (inst->disp_len == 1 || inst->disp_len == 4)
                    sprintf(expr, "[%s + %s * %d + 0x%x]", base_table[base_idx], base_table[index_idx], scale_val, inst->displacement);
                else
                    sprintf(expr, "[%s + %s * %d]", base_table[base_idx], base_table[index_idx], scale_val);
            }
        }
    } else {
        if (inst->mod == 0 && inst->rm == 5) {
            if (inst->is_32bit) {
                /* 32-bit Mode absolute displacement lookup entry point [disp32] */
                sprintf(expr, "[0x%x]", inst->displacement);
            } else {
                /* 64-bit Mode RIP-relative tracking bounds */
                sprintf(expr, "[rip + 0x%x]", inst->displacement);
            }
        } else {
            uint8_t rm_reg = inst->rm + (inst->rex_b << 3);
            if (inst->disp_len == 1 || inst->disp_len == 4)
                sprintf(expr, "[%s + 0x%x]", base_table[rm_reg], inst->displacement);
            else
                sprintf(expr, "[%s]", base_table[rm_reg]);
        }
    }
    sprintf(buf, "%s%s", seg_str, expr);
}

/**
 * @brief Standalone Intel Disassembler Component.
 *        Copies raw mnemonic strings into the destination buffer `out_asm`.
 *        The `do_print` parameter controls whether it outputs cleanly to stdout.
 */
uint32_t print_assembly_standalone_engine(const unsigned char *b, struct user_regs_struct *regs, char *out_asm, bool do_print, bool is_32bit) {
    x86_instruction_t inst;
    uint32_t consumed = decode_intel_format(b, &inst, is_32bit);

    uint8_t reg_idx = inst.reg + (inst.rex_r << 3);
    uint8_t rm_idx  = inst.rm + (inst.rex_b << 3);

    char asm_buf[128] = "";
    char comment_buf[128] = "";

    if (inst.opcode_len == 1) {
        switch (inst.opcode[0]) {
            /* 32-bit Single Byte Inc / Dec operational overrides (0x40 - 0x4F) */
            case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4a: case 0x4b: case 0x4c: case 0x4d: case 0x4e: case 0x4f: {
                if (is_32bit) {
                    uint8_t target_reg = inst.opcode[0] & 7;
                    const char *op_name = (inst.opcode[0] >= 0x48) ? "dec" : "inc";
                    sprintf(asm_buf, "%-7s %s", op_name, REG_32[target_reg]);
                    inst.total_len = consumed;
                }
                break;
            }
            /* Explicit INT3 Trap Decoders preventing layout string confusion */
            case 0xcc: {
                sprintf(asm_buf, "int3");
                inst.total_len = consumed;
                break;
            }
            /* Explicit Interrupt Vector configuration parsing */
            case 0xcd: {
                uint8_t int_num = b[consumed];
                inst.total_len = consumed + 1;
                sprintf(asm_buf, "%-7s 0x%02x", "int", int_num);
                if (int_num == 0x80) {
                    sprintf(comment_buf, "# 32-bit Linux Syscall Target");
                }
                break;
            }
            /* Memory Offset Moves without ModR/M components (0xA1 / 0xA3) */
            case 0xa1: case 0xa3: {
                if (is_32bit) {
                    inst.immediate = read_imm32(b, consumed);
                    inst.total_len = consumed + 4;
                    if (inst.opcode[0] == 0xa1) {
                        sprintf(asm_buf, "%-7s eax, [0x%x]", "mov", inst.immediate);
                    } else {
                        sprintf(asm_buf, "%-7s [0x%x], eax", "mov", inst.immediate);
                    }
                } else {
                    if (inst.rex_w) {
                        uint64_t imm64 = (uint64_t)b[consumed] | ((uint64_t)b[consumed+1] << 8) |
                        ((uint64_t)b[consumed+2] << 16) | ((uint64_t)b[consumed+3] << 24) |
                        ((uint64_t)b[consumed+4] << 32) | ((uint64_t)b[consumed+5] << 40) |
                        ((uint64_t)b[consumed+6] << 48) | ((uint64_t)b[consumed+7] << 56);
                        inst.total_len = consumed + 8;
                        if (inst.opcode[0] == 0xa1) {
                            sprintf(asm_buf, "%-7s rax, [0x%llx]", "mov", (unsigned long long)imm64);
                        } else {
                            sprintf(asm_buf, "%-7s [0x%llx], rax", "mov", (unsigned long long)imm64);
                        }
                    } else {
                        inst.immediate = read_imm32(b, consumed);
                        inst.total_len = consumed + 4;
                        if (inst.opcode[0] == 0xa1) {
                            sprintf(asm_buf, "%-7s eax, [0x%x]", "mov", inst.immediate);
                        } else {
                            sprintf(asm_buf, "%-7s [0x%x], eax", "mov", inst.immediate);
                        }
                    }
                }
                break;
            }
            case 0x74: case 0x75: case 0xeb: {
                int8_t rel8 = (int8_t)b[consumed];
                inst.total_len = consumed + 1;
                const char *jmp_name = (inst.opcode[0] == 0x74) ? "je" : (inst.opcode[0] == 0x75) ? "jne" : "jmp";
                sprintf(asm_buf, "%-7s short 0x%x", jmp_name, (uint8_t)rel8);
                if (regs != NULL) {
                    uint64_t target = regs->rip + inst.total_len + rel8;
                    sprintf(comment_buf, "# Target Branch Address: 0x%llx", (unsigned long long)target);
                }
                break;
            }
            case 0x50: case 0x51: case 0x52: case 0x53:
            case 0x54: case 0x55: case 0x56: case 0x57: {
                uint8_t direct_reg = (inst.opcode[0] & 7) + (inst.rex_b << 3);
                if (!inst.has_prefix_66 && !is_32bit) inst.operand_size = 64;
                sprintf(asm_buf, "%-7s %s", "push", get_reg_name(direct_reg, &inst));
                inst.total_len = consumed;
                break;
            }
            case 0x58: case 0x59: case 0x5a: case 0x5b:
            case 0x5c: case 0x5d: case 0x5e: case 0x5f: {
                uint8_t direct_reg = (inst.opcode[0] & 7) + (inst.rex_b << 3);
                if (!inst.has_prefix_66 && !is_32bit) inst.operand_size = 64;
                sprintf(asm_buf, "%-7s %s", "pop", get_reg_name(direct_reg, &inst));
                inst.total_len = consumed;
                break;
            }
            case 0xe8: {
                inst.immediate = read_imm32(b, consumed);
                inst.total_len = consumed + 4;
                sprintf(asm_buf, "%-7s 0x%x", "call", inst.immediate);
                if (regs != NULL) {
                    uint64_t target = regs->rip + inst.total_len + inst.immediate;
                    sprintf(comment_buf, "# Target Call Address: 0x%llx", (unsigned long long)target);
                }
                break;
            }
            case 0xc3: {
                sprintf(asm_buf, "ret");
                inst.total_len = consumed;
                break;
            }
            case 0xb8: case 0xb9: case 0xba: case 0xbb:
            case 0xbc: case 0xbd: case 0xbe: case 0xbf: {
                uint8_t direct_reg = (inst.opcode[0] & 7) + (inst.rex_b << 3);
                if (inst.has_prefix_66) {
                    inst.immediate = read_imm16(b, consumed);
                    inst.total_len = consumed + 2;
                } else {
                    inst.immediate = read_imm32(b, consumed);
                    inst.total_len = consumed + 4;
                }
                sprintf(asm_buf, "%-7s %s, 0x%x", "mov", get_reg_name(direct_reg, &inst), inst.immediate);
                break;
            }
            case 0x00: case 0x01: {
                const char *reg_str = get_reg_name(reg_idx, &inst);
                if (inst.mod == 3) {
                    sprintf(asm_buf, "%-7s %s, %s", "add", get_reg_name(rm_idx, &inst), reg_str);
                } else {
                    char mem_buf[64]; format_memory_operand(&inst, mem_buf);
                    sprintf(asm_buf, "%-7s %s, %s", "add", mem_buf, reg_str);
                }
                inst.total_len = consumed;
                break;
            }
            case 0x30: case 0x31: {
                const char *reg_str = get_reg_name(reg_idx, &inst);
                if (inst.mod == 3) {
                    sprintf(asm_buf, "%-7s %s, %s", "xor", get_reg_name(rm_idx, &inst), reg_str);
                } else {
                    char mem_buf[64]; format_memory_operand(&inst, mem_buf);
                    sprintf(asm_buf, "%-7s %s, %s", "xor", mem_buf, reg_str);
                }
                inst.total_len = consumed;
                break;
            }
            case 0x88: case 0x8b: {
                if (inst.opcode[0] == 0x88) {
                    if (inst.mod == 3) {
                        sprintf(asm_buf, "%-7s %s, %s", "mov", get_reg_name(rm_idx, &inst), get_reg_name(reg_idx, &inst));
                    } else {
                        char mem_buf[64]; format_memory_operand(&inst, mem_buf);
                        sprintf(asm_buf, "%-7s %s, %s", "mov", mem_buf, get_reg_name(reg_idx, &inst));
                    }
                } else {
                    if (inst.mod == 3) {
                        sprintf(asm_buf, "%-7s %s, %s", "mov", get_reg_name(reg_idx, &inst), get_reg_name(rm_idx, &inst));
                    } else {
                        char mem_buf[64]; format_memory_operand(&inst, mem_buf);
                        sprintf(asm_buf, "%-7s %s, %s", "mov", get_reg_name(reg_idx, &inst), mem_buf);
                    }
                }
                inst.total_len = consumed;
                break;
            }
            case 0x8a: {
                if (inst.mod == 3) {
                    sprintf(asm_buf, "%-7s %s, %s", "mov", get_reg_name(reg_idx, &inst), get_reg_name(rm_idx, &inst));
                } else {
                    char mem_buf[64]; format_memory_operand(&inst, mem_buf);
                    sprintf(asm_buf, "%-7s %s, %s", "mov", get_reg_name(reg_idx, &inst), mem_buf);
                }
                inst.total_len = consumed;
                break;
            }
            case 0x83: {
                inst.immediate = (int8_t)b[consumed];
                inst.total_len = consumed + 1;
                const char *op_name = "unknown";
                if (inst.reg == 0) op_name = "add";
                else if (inst.reg == 5) op_name = "sub";
                else if (inst.reg == 7) op_name = "cmp";

                if (inst.mod == 3) {
                    sprintf(asm_buf, "%-7s %s, 0x%x", op_name, get_reg_name(rm_idx, &inst), inst.immediate);
                } else {
                    char mem_buf[64]; format_memory_operand(&inst, mem_buf);
                    sprintf(asm_buf, "%-7s %s, 0x%x", op_name, mem_buf, inst.immediate);
                }
                break;
            }
            case 0xc6: case 0xc7: {
                if (inst.opcode[0] == 0xc6) {
                    inst.immediate = b[consumed];
                    inst.total_len = consumed + 1;
                } else {
                    inst.immediate = read_imm32(b, consumed);
                    inst.total_len = consumed + 4;
                }
                if (inst.mod == 3) {
                    sprintf(asm_buf, "%-7s %s, 0x%x", "mov", get_reg_name(rm_idx, &inst), inst.immediate);
                } else {
                    char mem_buf[64]; format_memory_operand(&inst, mem_buf);
                    sprintf(asm_buf, "%-7s %s, 0x%x", "mov", mem_buf, inst.immediate);
                }
                break;
            }
            case 0x8d: {
                char mem_buf[64]; format_memory_operand(&inst, mem_buf);
                sprintf(asm_buf, "%-7s %s, %s", "lea", REG_64[reg_idx], mem_buf);
                inst.total_len = consumed;
                if (inst.mod == 0 && inst.rm == 5 && regs != NULL && !is_32bit) {
                    uint64_t target = regs->rip + inst.total_len + inst.displacement;
                    sprintf(comment_buf, "# Target Address: 0x%llx", (unsigned long long)target);
                }
                break;
            }
            case 0xe9: {
                inst.immediate = read_imm32(b, consumed);
                inst.total_len = consumed + 4;
                sprintf(asm_buf, "%-7s 0x%x", "jmp", inst.immediate);
                if (regs != NULL) {
                    uint64_t target = regs->rip + inst.total_len + inst.immediate;
                    sprintf(comment_buf, "# Target Branch Address: 0x%llx", (unsigned long long)target);
                }
                break;
            }
            case 0xf6: case 0xf7: {
                inst.total_len = consumed;
                const char *op_name = "unknown";
                if (inst.reg == 4) op_name = "mul";
                else if (inst.reg == 5) op_name = "imul";
                else if (inst.reg == 6) op_name = "div";
                else if (inst.reg == 7) op_name = "idiv";

                if (inst.mod == 3) {
                    sprintf(asm_buf, "%-7s %s", op_name, get_reg_name(rm_idx, &inst));
                } else {
                    char mem_buf[64]; format_memory_operand(&inst, mem_buf);
                    sprintf(asm_buf, "%-7s %s", op_name, mem_buf);
                }
                break;
            }
            case 0xd0: case 0xd1: case 0xd2: case 0xd3: case 0xc0: case 0xc1: {
                uint8_t op_type = inst.opcode[0];
                uint8_t shift_amt = 1;
                bool has_imm_amt = (op_type == 0xc0 || op_type == 0xc1);

                if (has_imm_amt) {
                    shift_amt = b[consumed];
                    inst.total_len = consumed + 1;
                } else if (op_type == 0xd2 || op_type == 0xd3) {
                    shift_amt = 0;
                    inst.total_len = consumed;
                } else {
                    inst.total_len = consumed;
                }

                const char *op_name = "unknown";
                if (inst.reg == 0) op_name = "rol";
                else if (inst.reg == 1) op_name = "ror";
                else if (inst.reg == 4) op_name = "shl";
                else if (inst.reg == 5) op_name = "shr";
                else if (inst.reg == 7) op_name = "sar";

                char target_buf[64];
                if (inst.mod == 3) {
                    sprintf(target_buf, "%s", get_reg_name(rm_idx, &inst));
                } else {
                    format_memory_operand(&inst, target_buf);
                }

                if (has_imm_amt) {
                    sprintf(asm_buf, "%-7s %s, 0x%x", op_name, target_buf, shift_amt);
                } else if (op_type == 0xd2 || op_type == 0xd3) {
                    sprintf(asm_buf, "%-7s %s, cl", op_name, target_buf);
                } else {
                    sprintf(asm_buf, "%-7s %s, 1", op_name, target_buf);
                }
                break;
            }
            default: sprintf(asm_buf, "unknown 1-byte instruction (Opcode: 0x%02x)", inst.opcode[0]); inst.total_len = consumed; break;
        }
    }
    else if (inst.opcode_len == 2) {
        switch (inst.opcode[1]) {
            case 0x05: {
                sprintf(asm_buf, "syscall");
                inst.total_len = consumed;
                break;
            }
            case 0x84: case 0x85: {
                const char *j_name = (inst.opcode[1] == 0x84) ? "je" : "jne";
                inst.immediate = read_imm32(b, consumed);
                inst.total_len = consumed + 4;
                sprintf(asm_buf, "%-7s 0x%x", j_name, inst.immediate);
                if (regs != NULL) {
                    uint64_t target = regs->rip + inst.total_len + inst.immediate;
                    sprintf(comment_buf, "# Target Branch Address: 0x%llx", (unsigned long long)target);
                }
                break;
            }
            default: sprintf(asm_buf, "unknown 2-byte instruction (Opcode: 0x0f 0x%02x)", inst.opcode[1]); inst.total_len = consumed; break;
        }
    }

    char hex_buf[48] = "";
    char *hex_ptr = hex_buf;
    for (uint32_t i = 0; i < inst.total_len; i++) {
        hex_ptr += sprintf(hex_ptr, "%02x ", b[i]);
    }

    if (do_print) {
        printf("%-30s %s", hex_buf, asm_buf);
        if (comment_buf[0] != '\0') {
            printf("     %s", comment_buf);
        }
        printf("\n");
    }

    if (out_asm) {
        strcpy(out_asm, asm_buf);
    }

    return inst.total_len;
}

/**
 * @brief Live child context memory and stack trace hex dumper utility.
 */
void dump_memory(pid_t child, uint64_t addr, int words) {
    printf("\n--- Runtime Memory Dump at 0x%llx ---\n", (unsigned long long)addr);
    for (int i = 0; i < words; i++) {
        uint64_t current_addr = addr + (i * 8);
        long data = ptrace(PTRACE_PEEKDATA, child, current_addr, NULL);
        printf("0x%012llx: %016llx\n", (unsigned long long)current_addr, (unsigned long long)data);
    }
    printf("-----------------------------------------------------------\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <target_program_path>\n", argv[0]);
        return 1;
    }

    pid_t child = fork();

    if(child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(argv[1], argv[1], NULL);
        perror("execl failed");
        exit(1);
    }
    else {
        int status;
        struct user_regs_struct regs;
        long ins;
        int modified = 0;
        char user_input[64];
        char asm_buf[128];

        bool cont_mode = false;
        bool filter_active = false;
        char filter_str[32] = "";

        // Catch child process startup sequence signals
        wait(&status);

        while(1) {
            bool show_prompt = true;

            ptrace(PTRACE_GETREGS, child, NULL, &regs);

            /* Dynamic Bi-Mode Architecture Evaluation Tracking */
            bool is_32bit = (regs.cs == 0x23);

            /* Breakpoint Hit Evaluation Loop */
            int hit_idx = -1;
            for (int i = 0; i < bp_count; i++) {
                if (bp_active[i] && regs.rip == bp_addrs[i] + 1) {
                    hit_idx = i;
                    break;
                }
            }

            if (hit_idx != -1) {
                cont_mode = false;
                filter_active = false;
                show_prompt = true;

                printf("\n*** Breakpoint %d hit at address: 0x%llx ***\n", hit_idx, (unsigned long long)bp_addrs[hit_idx]);

                // Rewind instruction execution boundaries backward past INT3 trap
                regs.rip--;
                ptrace(PTRACE_SETREGS, child, NULL, &regs);

                // Re-inject original preserved operational machine byte
                ptrace(PTRACE_POKEDATA, child, bp_addrs[hit_idx], (void*)bp_orig_data[hit_idx]);

                // Display operational block info details before running step-over adjustments
                ins = ptrace(PTRACE_PEEKTEXT, child, regs.rip, NULL);
                printf("\n-------------------------------------------------------------------------------------------\n");
                printf("RIP: %06llx -> Machine Code: ", regs.rip);
                print_assembly_standalone_engine((unsigned char *)&ins, &regs, asm_buf, true, is_32bit);
                printf("-------------------------------------------------------------------------------------------\n");

                // Perform micro step-over sequence, wait, and re-arm trap address
                ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
                wait(&status);
                if (WIFEXITED(status)) {
                    printf("\n--- Child process exited normally ---\n");
                    break;
                }

                long trap_code = (bp_orig_data[hit_idx] & ~0xFF) | 0xCC;
                ptrace(PTRACE_POKEDATA, child, bp_addrs[hit_idx], (void*)trap_code);

                // Sync baseline trace state
                ptrace(PTRACE_GETREGS, child, NULL, &regs);
                is_32bit = (regs.cs == 0x23);
            }

            /* Standard Memory Patch Handler */
            if (regs.rip == 0x40101c && !modified) {
                long data = ptrace(PTRACE_PEEKDATA, child, regs.rsi, NULL);
                unsigned char *str_bytes = (unsigned char *)&data;
                str_bytes[0] = 'G';
                ptrace(PTRACE_POKEDATA, child, regs.rsi, (void*)data);
                modified = 1;
            }

            ins = ptrace(PTRACE_PEEKTEXT, child, regs.rip, NULL);
            asm_buf[0] = '\0';

            if (cont_mode) show_prompt = false;

            if (filter_active) {
                // Peek lookahead without spamming stdout during automated scan passes
                print_assembly_standalone_engine((unsigned char *)&ins, &regs, asm_buf, false, is_32bit);
                if (strstr(asm_buf, filter_str) == NULL) {
                    show_prompt = false;
                } else {
                    cont_mode = false;
                    filter_active = false;
                    show_prompt = true;
                    printf("\n[Filter Target Matched: '%s']\n", filter_str);
                    printf("\n-------------------------------------------------------------------------------------------\n");
                    printf("RIP: %06llx -> Machine Code: ", regs.rip);
                    print_assembly_standalone_engine((unsigned char *)&ins, &regs, asm_buf, true, is_32bit);
                    printf("-------------------------------------------------------------------------------------------\n");
                }
            } else {
                if (show_prompt) {
                    printf("\n-------------------------------------------------------------------------------------------\n");
                }
                printf("RIP: %06llx -> Machine Code: ", regs.rip);
                print_assembly_standalone_engine((unsigned char *)&ins, &regs, asm_buf, true, is_32bit);
                if (show_prompt) {
                    printf("-------------------------------------------------------------------------------------------\n");
                }
            }

            if (show_prompt) {
                printf("Commands: [Enter/n] Step, [c] Continue, [b <hex_addr>] Break, [m <hex_addr> <words>] Mem, [s] Stack, [f <str>] Filter\n");
                printf("jdebug> ");
                if (fgets(user_input, sizeof(user_input), stdin) == NULL) break;

                if (user_input[0] == '\n' || user_input[0] == 'n' || user_input[0] == 'N') {
                    ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
                    wait(&status);
                }
                else if (user_input[0] == 'c' || user_input[0] == 'C') {
                    cont_mode = true;
                    ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
                    wait(&status);
                }
                else if (user_input[0] == 'b' || user_input[0] == 'B') {
                    uint64_t b_addr = 0;
                    if (sscanf(user_input + 1, "%llx", (unsigned long long *)&b_addr) == 1) {
                        if (bp_count < MAX_BPS) {
                            long orig = ptrace(PTRACE_PEEKTEXT, child, b_addr, NULL);
                            bp_addrs[bp_count] = b_addr;
                            bp_orig_data[bp_count] = orig;
                            bp_active[bp_count] = true;

                            long trap = (orig & ~0xFF) | 0xCC;
                            ptrace(PTRACE_POKEDATA, child, b_addr, (void*)trap);
                            printf("[*] Breakpoint %d set successfully at target: 0x%llx\n", bp_count, (unsigned long long)b_addr);
                            bp_count++;
                        } else {
                            printf("[-] Breakpoint register limit exhausted.\n");
                        }
                    } else {
                        printf("[-] Invalid syntax. Usage example: b 4000d8\n");
                    }
                    continue;
                }
                else if (user_input[0] == 'm' || user_input[0] == 'M') {
                    uint64_t m_addr = 0;
                    int count = 4;
                    if (sscanf(user_input + 1, "%llx %d", (unsigned long long *)&m_addr, &count) >= 1) {
                        dump_memory(child, m_addr, count);
                    } else {
                        printf("[-] Invalid syntax. Usage example: m 4010f4 4\n");
                    }
                    continue;
                }
                else if (user_input[0] == 's' || user_input[0] == 'S') {
                    dump_memory(child, regs.rsp, 4);
                    continue;
                }
                else if (user_input[0] == 'f' || user_input[0] == 'F') {
                    if (sscanf(user_input + 1, "%s", filter_str) == 1) {
                        filter_active = true;
                        cont_mode = true;
                        printf("[*] Fast-forwarding tracing context until mnemonic matches: '%s'\n", filter_str);
                        ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
                        wait(&status);
                    } else {
                        printf("[-] Invalid syntax. Usage example: f syscall\n");
                        continue;
                    }
                }
            } else {
                ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
                wait(&status);
            }

            if (WIFEXITED(status)) {
                printf("\n--- Child process exited normally ---\n");
                break;
            }

            /* Display operational diagnostic registers metrics block */
            if (show_prompt || cont_mode == false) {
                ptrace(PTRACE_GETREGS, child, NULL, &regs);
                printf("\nRAX: %016llx  RBX: %016llx  RCX: %016llx  RDX: %016llx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
                printf("RSI: %016llx  RDI: %016llx  RBP: %016llx  RSP: %016llx\n", regs.rsi, regs.rdi, regs.rbp, regs.rsp);
                printf(" R8: %016llx   R9: %016llx  R10: %016llx  R11: %016llx\n", regs.r8, regs.r9, regs.r10, regs.r11);
                printf("R12: %016llx  R13: %016llx  R14: %016llx  R15: %016llx\n", regs.r12, regs.r13, regs.r14, regs.r15);
                printf("\t\t\t\t  EFLAGS: %016llx\n", regs.eflags);
                printf("-------------------------------------------------------------------------------------------\n");
            }
        }
    }
    return 0;
}
