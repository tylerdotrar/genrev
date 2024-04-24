# genrev
Modular Python script that uses the Python `keystone-engine` library to convert Intel (x86) assembly into Windows shellcode.

## Description

**The shellcode does the following:**

1. Stores `Kernel32.dll` pointer into EBX and `find_function()` pointer into `[ebp+0x04]`.
2. Acquires and stores pointers to required Win32 API calls into offsets `[ebp+0x10]` through `[ebp+0x24]`.
3. Establishes socket connection to a listening port via `WSAStartup()`, `WSASocketA()`, and `WSAConnect()`.
4. Creates STARTUPINFO struct that inherits socket handles for standard input, output, and error.
5. Creates a `powershell.exe` (or `cmd.exe`) process with inherited handles via `CreateProcessA()`.
6. Gracefully exits upon closure via `TerminateProcess()`.

---

**By default, the shellcode is returned in two formats:**

- one large string of bytes
- a formatted string of 16-byte chunks

![image](https://github.com/tylerdotrar/genrev/assets/69973771/805c32dc-cb6e-48ab-b73b-b3e0a8d488b7)


## Usage

```
Usage: gen_rev.py [options]

Options:
  <attackerIP>    -->  IP address to connect to                        (default: 127.0.0.1)
  <attackerPort>  -->  NOT WORKING YET: Listening port to connect to   (default: 443)
  --cmd           -->  Target shell uses 'cmd.exe' instead of 'powershell.exe'
  --dbg           -->  Execute shellcode, allowing attachment to the process
  --help          -->  Return help message
```
_(Note: the `--dbg` arguments copies the shellcode into memory and attempts to execute it; this was used for debugging via `WinDbg`)_

![image](https://github.com/tylerdotrar/genrev/assets/69973771/aa1f949c-7dd7-4df7-b36d-675371e1ae5b)

![image](https://github.com/tylerdotrar/genrev/assets/69973771/8d1c3beb-5915-4f4f-9792-489538781178)

