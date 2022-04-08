#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include <stdint.h>
#include <stdarg.h>
#include "ia32.h"
#pragma comment(lib, "ntoskrnl.lib" )

uint64_t count = 0;

void log_success(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vDbgPrintExWithPrefix("[SUCCESS] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
    va_end(args);

    count++;
}

void log_debug(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vDbgPrintExWithPrefix("[DEBUG] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
    va_end(args);

    count++;
}

void log_error(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vDbgPrintExWithPrefix("[ERROR] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
    va_end(args);

    count++;
}


union __cr_fixed_t
{
    struct
    {
        unsigned long low;
        long high;
    } split;
    struct
    {
        unsigned long low;
        long high;
    } u;
    long long all;
};

void adjust_control_registers(void)
{
    CR4 cr4 = { 0 };
    CR0 cr0 = { 0 };
    union __cr_fixed_t cr_fixed;

    cr_fixed.all = __readmsr(IA32_VMX_CR0_FIXED0);
    cr0.Flags = __readcr0();
    cr0.Flags |= cr_fixed.split.low;
    cr_fixed.all = __readmsr(IA32_VMX_CR0_FIXED1);
    cr0.Flags &= cr_fixed.split.low;
    __writecr0(cr0.Flags);

    cr_fixed.all = __readmsr(IA32_VMX_CR4_FIXED0);
    cr4.Flags = __readcr4();
    cr4.Flags |= cr_fixed.split.low;
    cr_fixed.all = __readmsr(IA32_VMX_CR4_FIXED1);
    cr4.Flags &= cr_fixed.split.low;
    __writecr4(cr4.Flags);
}

uint8_t supports_vmx_operation(void)
{
    int cpuid[4];
    __cpuid(cpuid, 1);

    if (CPUID_FEATURE_INFORMATION_ECX_VIRTUAL_MACHINE_EXTENSIONS(cpuid[2]))
    {
        return TRUE;
    }

    return FALSE;
}

uint8_t enable_vmx_operation(void)
{
    CR4 cr4 = { 0 };
    IA32_FEATURE_CONTROL_REGISTER feature_control = { 0 };

    cr4.Flags = __readcr4();
    cr4.VmxEnable = 1;

    __writecr4(cr4.Flags);
    feature_control.Flags = __readmsr(IA32_FEATURE_CONTROL);

    if (feature_control.LockBit == 0)
    {
        feature_control.EnableVmxOutsideSmx = 1;
        feature_control.LockBit = 1;

        __writemsr(IA32_FEATURE_CONTROL, feature_control.Flags);
        return TRUE;
    }
    return FALSE;
}

void disable_vmx_operation(void)
{
    CR4 cr4 = { 0 };
    IA32_FEATURE_CONTROL_REGISTER feature_control = { 0 };

    cr4.Flags = __readcr4();
    cr4.VmxEnable = 0;

    __writecr4(cr4.Flags);
    feature_control.Flags = __readmsr(IA32_FEATURE_CONTROL);


    feature_control.EnableVmxOutsideSmx = 0;
    feature_control.LockBit = 0;

    __writemsr(IA32_FEATURE_CONTROL, feature_control.Flags);
}


typedef struct __vcpu
{
    VMCS* vmcs;
    uint64_t vmcs_physical;

    VMXON* vmxon;
    uint64_t vmxon_physical;
} vpcu, * pvcpu;

uint8_t alloc_vmcs(pvcpu vcpu)
{
    IA32_VMX_BASIC_REGISTER vmx_basic = { 0 };
    PHYSICAL_ADDRESS physical_max;

    vmx_basic.Flags = __readmsr(IA32_VMX_BASIC);
    physical_max.QuadPart = 0xffff'ffff'ffff'ffffULL;

    vcpu->vmcs = (VMCS*)MmAllocateContiguousMemory(PAGE_SIZE, physical_max);
    if (!vcpu->vmcs)
    {
        log_error("Failed to allocate VMCS for vCPU %u. MmAllocateContiguousMemory failed.\n", KeGetCurrentProcessorNumber());
        return FALSE;
    }

    vcpu->vmcs_physical = MmGetPhysicalAddress(vcpu->vmcs).QuadPart;
    RtlSecureZeroMemory(vcpu->vmcs, PAGE_SIZE);

    vcpu->vmcs->RevisionId = vmx_basic.VmcsRevisionId;
    vcpu->vmcs->ShadowVmcsIndicator = 0;

    return TRUE;
}

void free_vmcs(pvcpu vcpu)
{
    MmFreeContiguousMemory(vcpu->vmcs);
}

uint8_t alloc_vmxon(pvcpu vcpu)
{
    IA32_VMX_BASIC_REGISTER vmx_basic = { 0 };
    PHYSICAL_ADDRESS physical_max = { 0 };

    if (!vcpu)
    {
        log_error("Failed to allocate VMXON region. vCPU was null.\n");
        return FALSE;
    }

    vmx_basic.Flags = __readmsr(IA32_VMX_BASIC);
    physical_max.QuadPart = MAXULONG64;

    if (vmx_basic.VmcsSizeInBytes > PAGE_SIZE)
    {
        vcpu->vmxon = (VMXON*)MmAllocateContiguousMemory(vmx_basic.VmcsSizeInBytes, physical_max);
    }
    else
    {
        vcpu->vmxon = (VMXON*)MmAllocateContiguousMemory((ULONG64)PAGE_SIZE, physical_max);
    }

    if (!vcpu->vmxon)
    {
        log_error("Failed to allocate VMXON region. MmAllocateContiguousMemory failed.\n");
        return FALSE;
    }

    vcpu->vmxon_physical = MmGetPhysicalAddress(vcpu->vmxon).QuadPart;

    RtlSecureZeroMemory(vcpu->vmxon, PAGE_SIZE);

    vcpu->vmxon->RevisionId = vmx_basic.VmcsRevisionId;

    log_debug("VMXON for vcpu %d allocated. VA: %llX. PA: %llX. REV: %X.\n",
        KeGetCurrentProcessorNumber(),
        vcpu->vmxon,
        vcpu->vmxon_physical,
        vcpu->vmxon->RevisionId);

    return TRUE;
}

void free_vmxon(pvcpu vcpu)
{
    MmFreeContiguousMemory(vcpu->vmxon);
}

uint8_t alloc_vcpu(pvcpu vcpu)
{
    if (!alloc_vmcs(vcpu))
    {
        return FALSE;
    }

    if (!alloc_vmxon(vcpu))
    {
        free_vmcs(vcpu);
        return FALSE;
    }
}

void free_vcpu(pvcpu vcpu)
{
    free_vmcs(vcpu);
    free_vmxon(vcpu);
}


typedef struct __vmm
{
    pvcpu vcpu_array;
    uint32_t vcpu_count;

    void* stack;
} vmm, * pvmm;

uint8_t alloc_vmm(pvmm vmm)
{
    vmm = ExAllocatePool(NonPagedPool, sizeof(struct __vmm));
    if (!vmm)
    {
        log_error("Failed to allocate VMM.\n");
        return FALSE;
    }

    vmm->vcpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    vmm->vcpu_array = ExAllocatePool(NonPagedPool, sizeof(struct __vcpu) * vmm->vcpu_count);
    if (!vmm->vcpu_array)
    {
        log_error("Failed to allocate vCPU array for VMM.\n");
        ExFreePool(vmm);
        return FALSE;
    }

    vmm->stack = ExAllocatePool(NonPagedPool, 4096 * 8);
    if (!vmm->stack)
    {
        log_error("Failed to allocate VMM stack.\n");
        ExFreePool(vmm->vcpu_array);
        ExFreePool(vmm);
        return FALSE;
    }

    memset(vmm->stack, 0xCC, 4096 * 8);

    log_success("VMM, VMXON, and VMCS allocated for processor %X:\n\t vCPU array: %llX\n\t VMM stack: %llX\n\t Processor count %X\n\n", KeGetCurrentProcessorNumber(), vmm, vmm->vcpu_array, vmm->stack, vmm->vcpu_count);

    for (uint32_t current_vcpu = 0; current_vcpu < vmm->vcpu_count; current_vcpu++)
    {
        if (!alloc_vcpu(&vmm->vcpu_array[current_vcpu]))
        {
            // unwind actions
            return FALSE;
        }
    }

    return TRUE;
}

void free_vmm(pvmm vmm)
{
    ExFreePool(vmm->vcpu_array);
    ExFreePool(vmm->stack);
}

uint8_t vmxon_single_core(pvmm vmm)
{
    uint32_t processor_number = KeGetCurrentProcessorNumber();

    adjust_control_registers();

    if (!supports_vmx_operation())
    {
        log_error("Cannot put processor %X in VMX operation. VMX operation is not supported on this processor.\n", KeGetCurrentProcessorNumber());
        ExFreePool(vmm);
        return FALSE;
    }

    if (__vmx_on(&vmm->vcpu_array[processor_number].vmxon_physical) != 0)
    {
        log_error("Failed to put vCPU %d into VMX operation.\n", processor_number);
        ExFreePool(vmm);
        return FALSE;
    }

    log_success("vCPU %d is now in VMX operation.\n", KeGetCurrentProcessorNumber());

    return TRUE;
}

NTSTATUS GsDriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
    pvmm test_vmm = 0;
    if (!alloc_vmm(test_vmm))
    {
        log_error("Could not allocate VMM.\n");
        return STATUS_UNSUCCESSFUL;
    }

    KeIpiGenericCall((PKIPI_BROADCAST_WORKER)vmxon_single_core, test_vmm);

    log_debug("Test finished.\n");
    return STATUS_SUCCESS;
}