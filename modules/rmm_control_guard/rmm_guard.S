.intel_syntax noprefix
.bss
.align 8
rmm_key: .quad 0

.text
.globl rmm_init
.type rmm_init, @function
rmm_init:
    movabs rax, 0x494E414D4F52455A
    xor rdi, rax
    mov [rip + rmm_key], rdi
    xor eax, eax
    ret

.globl rmm_process_frame
.type rmm_process_frame, @function
rmm_process_frame:
    xor eax, eax
    test rdi, rdi
    jz .Ldone
    cmp rsi, 78
    jb .Ldone
    mov rax, [rip + rmm_key]
    crc32 rax, qword ptr [rdi + 70]
    crc32 rax, qword ptr [rdi + 54]
    mov rdx, [rdi + 62]
    mov ecx, 1
    xor r8d, r8d
    cmp rax, rdx
    cmove ecx, r8d
    mov eax, ecx
.Ldone:
    ret

.globl rmm_shutdown
.type rmm_shutdown, @function
rmm_shutdown:
    mov qword ptr [rip + rmm_key], 0
    ret

.section .data.rel.ro,"aw",@progbits
mod_name: .asciz "rmm_pure_x86_64_asm_guard"
.align 8
.globl zero_module_entry
zero_module_entry:
    .quad 0x494E414D4F52455A
    .long 1
    .long 10
    .quad mod_name
    .quad rmm_init
    .quad rmm_process_frame
    .quad rmm_shutdown
.section .note.GNU-stack,"",@progbits
