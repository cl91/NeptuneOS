.section .text
.global LdrInitializeThunk
LdrInitializeThunk:
    /* MSVC amd64 calling convention requires that the caller allocates
     * a 32-byte shadow area for rcx, rdx, r8 and r9
     */
    subq $0x20, %rsp

    /*
     * The virtual address of the IPC buffer is in %rcx.
     * The system dll tls region address is in %rdx.
     */
    call LdrpInitialize

    /* Should not return. */
1:
    jmp  1b
