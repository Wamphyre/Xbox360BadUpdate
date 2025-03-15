# WORK IN PROGRESS, DON'T USE

# BadUpdate Exploit for Xbox 360

This exploit allows you to run unsigned code on Xbox 360 by exploiting a vulnerability in the system update process.

## Overview

The BadUpdate Exploit is a multi-stage exploitation chain that leverages a race condition in encrypted data decompression to achieve arbitrary code execution in the Xbox 360 hypervisor. The exploit consists of four stages:

1. **Stage 1**: Initial game exploit to run a ROP chain
2. **Stage 2**: Complex ROP chain that attacks encrypted memory to obtain code execution
3. **Stage 3**: Code that performs an attack on the bootloader update process
4. **Stage 4**: Code that runs in hypervisor mode to patch security checks

## Features

- Works on Xbox 360 with kernel 17559 (retail)
- Improved success rate (~50-60%)
- No additional hardware required
- Allows running homebrew and unsigned applications

## Compatible Games

Currently, the exploit is compatible with:
- Rock Band Blitz
- Tony Hawk's American Wasteland

## Requirements

- Xbox 360 with retail kernel 17559
- One of the compatible games
- USB drive formatted in FAT32
- Compiled exploit files

## Compilation

To compile the exploit, run the `build_exploit.bat` script from the root directory. This script automatically:

1. Compiles all stages of the exploit (1-4)
2. Generates the necessary binary files
3. Places them in the correct output directory

```
build_exploit.bat
```

## Installation and Usage

1. **Prepare the USB drive**:
   - Format the USB drive in FAT32
   - Create a folder named `BadUpdatePayload` in the root
   - Copy all .bin files from the output folder to `BadUpdatePayload`:
     - BadUpdateExploit-Data.bin
     - BadUpdateExploit-2ndStage.bin
     - BadUpdateExploit-3rdStage.bin
     - BadUpdateExploit-4thStage.bin
     - update_data.bin
     - xke_update.bin
   - Add a `default.xex` file (the unsigned application you want to run)

2. **Run the exploit**:
   - Connect the USB drive to the Xbox 360
   - Start Rock Band Blitz (or Tony Hawk's American Wasteland)
   - Load the modified save (if necessary)
   - The exploit will run automatically

3. **Progress indicators**:
   - The ring of light LEDs will show progress:
     - Orange LED (red + green): Exploit start
     - Blinking LED: Searching for vulnerability
     - Green LED: Exploit successfully completed

## Execution Notes

- The exploit has a probabilistic nature and may require several attempts
- The complete process can take between 5-20 minutes
- In case of failure, restart the console and try again
- The success rate is approximately 50-60%

## Technical Operation

The exploit takes advantage of a race condition in the LZX decompression mechanism during system updates:

1. **L2 Cache Manipulation**: Locks 50% of L2 cache to create favorable conditions
2. **Whitening Collision**: Searches for specific whitening values for encrypted memory
3. **Race Condition**: Exploits a race condition in the decompression of block 14
4. **Code Execution**: Achieves code execution in the hypervisor to patch security

For more technical details, see the comments in the source code.

## Implemented Optimizations

Careful optimizations have been made to improve the exploit's success rate while maintaining stability:

1. **Improved Collision Detection**: Greater precision in identifying whitening values
2. **Optimized Cache Flush**: Multiple passes to ensure memory coherence
3. **Refined Timing**: Strategic small pauses to improve stability
4. **Enhanced Error Handling**: Better recovery from unexpected conditions
5. **Informative LED Patterns**: Better visualization of progress

## Limitations

- Only works on retail kernel 17559
- Not compatible with consoles that have had their CPU key changed
- Requires restarting the console after each use
- Does not install a permanent firmware

## Troubleshooting

1. **The exploit crashes immediately**:
   - Verify that you have copied all files correctly
   - Make sure you're using a compatible USB drive
   - Confirm you're using the correct game

2. **LEDs remain static**:
   - The exploit might be stuck in an early phase
   - Restart the console and try again

3. **default.xex doesn't load**:
   - Verify the file is in the correct location
   - Make sure the file is a valid XEX

4. **The console freezes after several minutes**:
   - This is normal, the exploit is working in the background
   - Let the process continue, it can take up to 20 minutes

## Credits

- **Grimdoomer**: Original exploit author
- **Xbox 360 Community**: For their continued support and contributions