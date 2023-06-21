.section .text.trap_handler
.option norvc
la x1, tohost
li x2, 3 # fail
sw x2, 0(x1)

.section .tohost
.globl tohost
tohost: .quad 0
.globl fromhost
fromhost: .quad 0
.globl itercount
itercount: .quad 0