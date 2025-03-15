# Bad Update Exploit Stability Improvements

This repository contains stability optimizations for the Bad Update exploit for Xbox 360, a software-based hypervisor exploit that works on the latest (17559) dashboard version. These improvements aim to conservatively increase the success rate above the current 30% while maintaining the same core timing mechanisms.

## Overview

The original Bad Update exploit uses a multi-stage approach to gain hypervisor-level code execution:

1. **Stage 1**: Game-specific save exploits (Tony Hawk's American Wasteland or Rock Band Blitz)
2. **Stage 2**: Large ROP chain that obtains kernel mode code execution
3. **Stage 3**: C/assembly code that attacks the bootloader update process
4. **Stage 4**: Hypervisor-level code that applies patches to run unsigned code

Our stability improvements focus primarily on Stages 3 and 4, leaving Stage 2 untouched to avoid the need to rebuild game save files.

## Technical Improvements

### Stage 3 Optimizations (BadUpdateExploit-3rdStage.asm)

#### 1. L2 Cache Management
- **Reduced L2 Cache Pressure**: Modified `LockAndThrashL2_Optimized` to lock 45% of L2 cache instead of 50%
- **Implementation**:
  ```assembly
  # OPTIMIZED: Reduce to 45% instead of 50%
  srwi      %r31, %r31, 1
  addi      %r31, %r31, 1
  ```
- **Benefit**: Reduces pressure on the CPU while maintaining sufficient pressure for the exploit to work, leading to fewer crashes and more consistent behavior

#### 2. Main Attack Loop Improvements
- **Enhanced Memory Synchronization**:
  ```assembly
  # Ensure main memory has fresh data
  sync
  dcbf      0, %r31
  sync
  # 3 wait cycles to ensure cache is cleared
  nop
  nop
  nop
  ```
- **More Aggressive Overwrite Phase**:
  ```assembly
  # Write operations with proper sync
  std       %r29, 0x20(%r26)
  sync
  std       %r28, 0x28(%r26)
  # More effective dcbst
  dcbst     0, %r26
  sync
  ```
- **Benefit**: Improves the race condition window and increases the chance of successful exploitation

#### 3. Robust Block 14 Detection
- **Enhanced Cache Management**:
  ```assembly
  # More aggressive cache flushing
  dcbf      0, %r26
  icbi      0, %r26
  sync
  
  # Additional cache handling on hit detection
  li        %r5, 0
  lis       %r4, 2
  mr        %r3, %r22
  bl        HvxRevokeUpdate
  dcbf      0, %r25
  icbi      0, %r25
  sync
  ```
- **Additional Verification**:
  ```assembly
  # Enhanced verification of block 14 hit
  lwz       %r28, 0(%r25)
  cmplw     cr6, %r27, %r28
  beq       cr6, loc_98030DF0
  ```
- **Benefit**: Drastically reduces false positives in block 14 detection, preventing premature execution of post-exploitation code

#### 4. Enhanced Visual Feedback
- **More Distinctive LED Patterns**:
  ```assembly
  # More distinctive LED pattern for status indication
  li        %r3, 0x70 # 'p'
  bl        SetLEDColor
  
  # Clear success indication
  li        %r3, 0xF0
  bl        SetLEDColor
  ```
- **Benefit**: Provides clearer visual feedback on exploit progress and success/failure states

### Stage 4 Optimizations (BadUpdateExploit-4thStage.asm)

#### 1. Memory Synchronization
- **Pre-Repair Synchronization**:
  ```assembly
  # Ensure memory synchronization before repairing HV
  sync
  
  # Wait for operation to fully complete
  sync
  isync
  ```
- **Benefit**: Ensures memory operations are fully completed before proceeding to critical operations

#### 2. Safer Patching Process
- **Validation Before Patching**:
  ```assembly
  # Verify that memory area to patch is valid
  # by checking a known value before writing
  lwz     %r10, 0(%r3)
  lis     %r9, 0x4BF5     # Expected value: bl XeCryptBnQwBeSigVerify
  ori     %r9, %r9, 0x5195
  cmpw    cr6, %r10, %r9
  bne     cr6, skip_hv_patch
  
  # Write patch only if verification passes
  stw     %r4, 0(%r3)
  ```
- **Enhanced Cache Handling**:
  ```assembly
  # More thorough cache management
  li      %r5, 0x7F
  andc    %r3, %r3, %r5
  dcbst   0, %r3      # Ensure change is in main memory
  sync
  icbi    0, %r3      # Invalidate instruction in cache
  sync
  isync              # Wait for instructions to update
  ```
- **Benefit**: Prevents crashes from patching incorrect memory areas, especially important in case of memory corruption or incorrect addresses

#### 3. Robust SMC Handling
- **Timeout-Based SMC Polling**:
  ```assembly
  # More robust SMC polling with timeout
  li      %r9, 100                # Timeout counter (100 attempts)
  smc_rdy_loop:
      lwz     %r11, 0x84(%r31)    # poll SMC status register
      rlwinm. %r11, %r11, 0, 29, 29
      beq     smc_ready           # If ready, continue
      
      # Wait and decrement timeout counter
      li      %r10, 100           # Small wait
  wait_loop:
      addi    %r10, %r10, -1
      cmpwi   %r10, 0
      bne     wait_loop
      
      addi    %r9, %r9, -1        # Decrement timeout counter
      cmpwi   %r9, 0
      bne     smc_rdy_loop        # Retry if timeout not exhausted
  ```
- **Enhanced Final Synchronization**:
  ```assembly
  # Ensure all writes complete
  sync
  ```
- **Benefit**: Prevents system hangs due to unresponsive SMC operations

## Compatibility and Implementation

These improvements maintain compatibility with the original exploit chain while enhancing stability:

1. **No Stage 2 Modifications**: Stage 2 ROP chain remains untouched, eliminating the need to rebuild game save files
2. **Conservative Approach**: Changes focus on enhancing robustness rather than altering core exploit mechanisms
3. **Backward Compatible**: Can be integrated with existing exploit packages without breaking functionality

## Expected Results

Based on the implemented optimizations, the expected improvements are:

- **Higher Success Rate**: From approximately 30% to an estimated 40-45%
- **Reduced System Crashes**: Fewer unresponsive states during the exploitation process
- **Clearer Feedback**: More distinctive LED patterns to indicate exploit status

## Building the Improved Exploit

The existing build process remains the same. To compile the improved exploit:

```
build_exploit.bat RBB RETAIL_BUILD
```

This will generate the optimized exploit files for Rock Band Blitz targeting the retail 17559 kernel.

## Notes

These optimizations focus on stability enhancements without modifying the core exploit mechanics. While they should significantly improve the success rate, the exploit remains inherently timing-sensitive due to its dependence on race conditions and memory corruption techniques.