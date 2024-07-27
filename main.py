from capstone import *
from keystone import *
import argparse

# Disassemble x86_64 binary
def disassemble_x86_64(binary_path):
    with open(binary_path, 'rb') as f:
        code = f.read()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = list(md.disasm(code, 0x1000))
    return instructions

# Translate x86_64 instructions to ARM64
def translate_instructions(x86_instructions):
    translated_instructions = []
    for ins in x86_instructions:
        arm64_instruction = translate_x86_to_arm64(ins)
        translated_instructions.extend(arm64_instruction)
    return translated_instructions

# Assemble ARM64 instructions into binary
def assemble_arm64(instructions, output_path):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_ARM)
    encoding, count = ks.asm('\n'.join(instructions))
    with open(output_path, 'wb') as f:
        f.write(bytearray(encoding))

# Extended translation logic for x86_64 to ARM64
def translate_x86_to_arm64(x86_ins):
    reg_mapping = {
        'rax': 'x0', 'rbx': 'x1', 'rcx': 'x2', 'rdx': 'x3',
        'rsi': 'x4', 'rdi': 'x5', 'rbp': 'x6', 'rsp': 'x7',
        'r8': 'x8', 'r9': 'x9', 'r10': 'x10', 'r11': 'x11',
        'r12': 'x12', 'r13': 'x13', 'r14': 'x14', 'r15': 'x15',
        'r16': 'x16', 'r17': 'x17', 'r18': 'x18', 'r19': 'x19',
        'r20': 'x20', 'r21': 'x21', 'r22': 'x22', 'r23': 'x23',
        'r24': 'x24', 'r25': 'x25', 'r26': 'x26', 'r27': 'x27',
        'r28': 'x28', 'r29': 'x29', 'r30': 'x30'
    }

    arm64_instructions = []

    def generate_arm64_instruction(opcode, operands):
        return f"{opcode} {' ,'.join(operands)}"

    def handle_immediate(operand):
        if operand.startswith('0x'):
            return f'#{operand}'
        return operand

    def parse_operands(op_str):
        return [op.strip() for op in op_str.split(',')]

    if x86_ins.mnemonic == 'mov':
        operands = parse_operands(x86_ins.op_str)
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            arm64_instructions.append(generate_arm64_instruction('mov', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))
        elif operands[1].startswith('0x'):
            arm64_instructions.append(generate_arm64_instruction('mov', [reg_mapping[operands[0]], handle_immediate(operands[1])]))

    elif x86_ins.mnemonic == 'add':
        operands = parse_operands(x86_ins.op_str)
        if len(operands) == 2 and operands[0] in reg_mapping and operands[1] in reg_mapping:
            arm64_instructions.append(generate_arm64_instruction('add', [reg_mapping[operands[0]], reg_mapping[operands[0]], reg_mapping[operands[1]]]))
        elif len(operands) == 3 and operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            arm64_instructions.append(generate_arm64_instruction('add', [reg_mapping[operands[0]], reg_mapping[operands[1]], reg_mapping[operands[2]]]))

    elif x86_ins.mnemonic == 'sub':
        operands = parse_operands(x86_ins.op_str)
        if len(operands) == 2 and operands[0] in reg_mapping and operands[1] in reg_mapping:
            arm64_instructions.append(generate_arm64_instruction('sub', [reg_mapping[operands[0]], reg_mapping[reg_mapping[operands[1]]], handle_immediate('0')]))
        elif len(operands) == 3 and operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            arm64_instructions.append(generate_arm64_instruction('sub', [reg_mapping[operands[0]], reg_mapping[operands[1]], reg_mapping[operands[2]]]))

    elif x86_ins.mnemonic == 'mul':
        operands = parse_operands(x86_ins.op_str)
        if len(operands) == 2 and operands[0] in reg_mapping and operands[1] in reg_mapping:
            arm64_instructions.append(generate_arm64_instruction('mul', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif x86_ins.mnemonic == 'div':
        operands = parse_operands(x86_ins.op_str)
        if len(operands) == 2 and operands[0] in reg_mapping and operands[1] in reg_mapping:
            arm64_instructions.append(generate_arm64_instruction('udiv', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif x86_ins.mnemonic == 'nop':
        arm64_instructions.append('nop')

    elif x86_ins.mnemonic == 'cmp':
        operands = parse_operands(x86_ins.op_str)
        if len(operands) == 2 and operands[0] in reg_mapping and operands[1] in reg_mapping:
            arm64_instructions.append(generate_arm64_instruction('cmp', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif x86_ins.mnemonic == 'jmp':
        arm64_instructions.append(f'b {x86_ins.op_str}')

    elif x86_ins.mnemonic == 'call':
        arm64_instructions.append(f'bl {x86_ins.op_str}')

    elif x86_ins.mnemonic == 'ret':
        arm64_instructions.append('ret')

    elif x86_ins.mnemonic == 'push':
        operands = parse_operands(x86_ins.op_str)
        if operands[0] in reg_mapping:
            arm64_instructions.append(f'stmd sp!, {{{reg_mapping[operands[0]]}}}')

    elif x86_ins.mnemonic == 'pop':
        operands = parse_operands(x86_ins.op_str)
        if operands[0] in reg_mapping:
            arm64_instructions.append(f'ldmd sp!, {{{reg_mapping[operands[0]]}}}')

    elif x86_ins.mnemonic == 'and':
        operands = parse_operands(x86_ins.op_str)
        if len(operands) == 3 and operands[0] in reg_mapping and operands[1] in reg_mapping:
            arm64_instructions.append(generate_arm64_instruction('and', [reg_mapping[operands[0]], reg_mapping[operands[1]], handle_immediate(operands[2])]))

    elif x86_ins.mnemonic == 'or':
        operands = parse_operands(x86_ins.op_str)
        if len(operands) == 3 and operands[0] in reg_mapping and operands[1] in reg_mapping:
            arm64_instructions.append(generate_arm64_instruction('orr', [reg_mapping[operands[0]], reg_mapping[operands[1]], handle_immediate(operands[2])]))

    elif x86_ins.mnemonic == 'xor':
        operands = parse_operands(x86_ins.op_str)
        if len(operands) == 3 and operands[0] in reg_mapping and operands[1] in reg_mapping:
            arm64_instructions.append(generate_arm64_instruction('eor', [reg_mapping[operands[0]], reg_mapping[operands[1]], handle_immediate(operands[2])]))

    elif x86_ins.mnemonic == 'shl':
        operands = parse_operands(x86_ins.op_str)
        if len(operands) == 2 and operands[0] in reg_mapping and operands[1] in reg_mapping:
            arm64_instructions.append(generate_arm64_instruction('lsl', [reg_mapping[operands[0]], reg_mapping[operands[1]], handle_immediate('1')]))

    elif x86_ins.mnemonic == 'shr':
        operands = parse_operands(x86_ins.op_str)
        if len(operands) == 2 and operands[0] in reg_mapping and operands[1] in reg_mapping:
            arm64_instructions.append(generate_arm64_instruction('lsr', [reg_mapping[operands[0]], reg_mapping[operands[1]], handle_immediate('1')]))

    elif x86_ins.mnemonic == 'sar':
        operands = parse_operands(x86_ins.op_str)
        if len(operands) == 2 and operands[0] in reg_mapping and operands[1] in reg_mapping:
            arm64_instructions.append(generate_arm64_instruction('asr', [reg_mapping[operands[0]], reg_mapping[operands[1]], handle_immediate('1')]))

    elif x86_ins.mnemonic == 'test':
        operands = parse_operands(x86_ins.op_str)
        if len(operands) == 2 and operands[0] in reg_mapping and operands[1] in reg_mapping:
            arm64_instructions.append(generate_arm64_instruction('tst', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif x86_ins.mnemonic == 'setcc':
        # Assuming setcc instruction sets flags based on the condition, might be translated to conditional branches
        arm64_instructions.append(f'ccmp {x86_ins.op_str}')

    elif x86_ins.mnemonic == 'cmovcc':
        # Conditional move based on flags, may need conditional branch handling
        arm64_instructions.append(f'csel {x86_ins.op_str}')

    return arm64_instructions

def main():
    parser = argparse.ArgumentParser(description='Translate x86_64 binary to ARM64 binary')
    parser.add_argument('-i', '--input', required=True, help='Path to the input x86_64 binary file')
    parser.add_argument('-o', '--output', required=True, help='Path to the output ARM64 binary file')
    args = parser.parse_args()

    x86_binary_path = args.input
    arm64_binary_path = args.output
    
    # Disassemble x86_64 binary
    x86_instructions = disassemble_x86_64(x86_binary_path)
    
    # Translate x86_64 instructions to ARM64
    arm64_instructions = translate_instructions(x86_instructions)
    
    # Assemble ARM64 instructions into new binary
    assemble_arm64(arm64_instructions, arm64_binary_path)
    print("Translation complete. ARM64 binary created at", arm64_binary_path)

if __name__ == "__main__":
    main()
