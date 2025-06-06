import argparse
import itertools
import sys

api_database = {
    "ntdll": {
        "name": "ntdll.dll",
        "functions": [
            "NtAcceptConnectPort",
            "NtAccessCheck",
            "NtAccessCheckAndAuditAlarm",
            "NtAccessCheckByType",
            "NtAccessCheckByTypeAndAuditAlarm",
            "NtAccessCheckByTypeResultList",
            "NtAccessCheckByTypeResultListAndAuditAlarm",
            "NtAccessCheckByTypeResultListAndAuditAlarmByHandle",
            "NtAcquireCrossVmMutant",
            "NtAcquireProcessActivityReference",
            "NtAddAtom",
            "NtAddAtomEx",
            "NtAddBootEntry",
            "NtAddDriverEntry",
            "NtAdjustGroupsToken",
            "NtAdjustPrivilegesToken",
            "NtAdjustTokenClaimsAndDeviceGroups",
            "NtAlertResumeThread",
            "NtAlertThread",
            "NtAlertThreadByThreadId",
            "NtAllocateLocallyUniqueId",
            "NtAllocateReserveObject",
            "NtAllocateUserPhysicalPages",
            "NtAllocateUserPhysicalPagesEx",
            "NtAllocateUuids",
            "NtAllocateVirtualMemory",
            "NtAllocateVirtualMemoryEx",
            "NtAlpcAcceptConnectPort",
            "NtAlpcCancelMessage",
            "NtAlpcConnectPort",
            "NtAlpcConnectPortEx",
            "NtAlpcCreatePort",
            "NtAlpcCreatePortSection",
            "NtAlpcCreateResourceReserve",
            "NtAlpcCreateSectionView",
            "NtAlpcCreateSecurityContext",
            "NtAlpcDeletePortSection",
            "NtAlpcDeleteResourceReserve",
            "NtAlpcDeleteSectionView",
            "NtAlpcDeleteSecurityContext",
            "NtAlpcDisconnectPort",
            "NtAlpcImpersonateClientContainerOfPort",
            "NtAlpcImpersonateClientOfPort",
            "NtAlpcOpenSenderProcess",
            "NtAlpcOpenSenderThread",
            "NtAlpcQueryInformation",
            "NtAlpcQueryInformationMessage",
            "NtAlpcRevokeSecurityContext",
            "NtAlpcSendWaitReceivePort",
            "NtAlpcSetInformation",
            "NtApphelpCacheControl",
            "NtAreMappedFilesTheSame",
            "NtAssignProcessToJobObject",
            "NtAssociateWaitCompletionPacket",
            "NtCallEnclave",
            "NtCallbackReturn",
            "NtCancelIoFile",
            "NtCancelIoFileEx",
            "NtCancelSynchronousIoFile",
            "NtCancelTimer",
            "NtCancelTimer2",
            "NtCancelWaitCompletionPacket",
            "NtChangeProcessState",
            "NtChangeThreadState",
            "NtClearEvent",
            "NtClose",
            "NtCloseObjectAuditAlarm",
            "NtCommitComplete",
            "NtCommitEnlistment",
            "NtCommitRegistryTransaction",
            "NtCommitTransaction",
            "NtCompactKeys",
            "NtCompareObjects",
            "NtCompareSigningLevels",
            "NtCompareTokens",
            "NtCompleteConnectPort",
            "NtCompressKey",
            "NtConnectPort",
            "NtContinue",
            "NtContinueEx",
            "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter",
            "NtCopyFileChunk",
            "NtCreateCpuPartition",
            "NtCreateCrossVmEvent",
            "NtCreateCrossVmMutant",
            "NtCreateDebugObject",
            "NtCreateDirectoryObject",
            "NtCreateDirectoryObjectEx",
            "NtCreateEnclave",
            "NtCreateEnlistment",
            "NtCreateEvent",
            "NtCreateEventPair",
            "NtCreateFile",
            "NtCreateIRTimer",
            "NtCreateIoCompletion",
            "NtCreateIoRing",
            "NtCreateJobObject",
            "NtCreateJobSet",
            "NtCreateKey",
            "NtCreateKeyTransacted",
            "NtCreateKeyedEvent",
            "NtCreateLowBoxToken",
            "NtCreateMailslotFile",
            "NtCreateMutant",
            "NtCreateNamedPipeFile",
            "NtCreatePagingFile",
            "NtCreatePartition",
            "NtCreatePort",
            "NtCreatePrivateNamespace",
            "NtCreateProcess",
            "NtCreateProcessEx",
            "NtCreateProcessStateChange",
            "NtCreateProfile",
            "NtCreateProfileEx",
            "NtCreateRegistryTransaction",
            "NtCreateResourceManager",
            "NtCreateSection",
            "NtCreateSectionEx",
            "NtCreateSemaphore",
            "NtCreateSymbolicLinkObject",
            "NtCreateThread",
            "NtCreateThreadEx",
            "NtCreateThreadStateChange",
            "NtCreateTimer",
            "NtCreateTimer2",
            "NtCreateToken",
            "NtCreateTokenEx",
            "NtCreateTransaction",
            "NtCreateTransactionManager",
            "NtCreateUserProcess",
            "NtCreateWaitCompletionPacket",
            "NtCreateWaitablePort",
            "NtCreateWnfStateName",
            "NtCreateWorkerFactory",
            "NtDebugActiveProcess",
            "NtDebugContinue",
            "NtDelayExecution",
            "NtDeleteAtom",
            "NtDeleteBootEntry",
            "NtDeleteDriverEntry",
            "NtDeleteFile",
            "NtDeleteKey",
            "NtDeleteObjectAuditAlarm",
            "NtDeletePrivateNamespace",
            "NtDeleteValueKey",
            "NtDeleteWnfStateData",
            "NtDeleteWnfStateName",
            "NtDeviceIoControlFile",
            "NtDirectGraphicsCall",
            "NtDisableLastKnownGood",
            "NtDisplayString",
            "NtDrawText",
            "NtDuplicateObject",
            "NtDuplicateToken",
            "NtEnableLastKnownGood",
            "NtEnumerateBootEntries",
            "NtEnumerateDriverEntries",
            "NtEnumerateKey",
            "NtEnumerateSystemEnvironmentValuesEx",
            "NtEnumerateTransactionObject",
            "NtEnumerateValueKey",
            "NtExtendSection",
            "NtFilterBootOption",
            "NtFilterToken",
            "NtFilterTokenEx",
            "NtFindAtom",
            "NtFlushBuffersFile",
            "NtFlushBuffersFileEx",
            "NtFlushInstallUILanguage",
            "NtFlushInstructionCache",
            "NtFlushKey",
            "NtFlushProcessWriteBuffers",
            "NtFlushVirtualMemory",
            "NtFlushWriteBuffer",
            "NtFreeUserPhysicalPages",
            "NtFreeVirtualMemory",
            "NtFreezeRegistry",
            "NtFreezeTransactions",
            "NtFsControlFile",
            "NtGetCachedSigningLevel",
            "NtGetCompleteWnfStateSubscription",
            "NtGetContextThread",
            "NtGetCurrentProcessorNumber",
            "NtGetCurrentProcessorNumberEx",
            "NtGetDevicePowerState",
            "NtGetInformationThread",
            "NtGetMUIRegistryInfo",
            "NtGetNextProcess",
            "NtGetNextThread",
            "NtGetNlsSectionPtr",
            "NtGetNotificationResourceManager",
            "NtGetTickCount",
            "NtGetWriteWatch",
            "NtImpersonateAnonymousToken",
            "NtImpersonateClientOfPort",
            "NtImpersonateThread",
            "NtInitializeEnclave",
            "NtInitializeNlsFiles",
            "NtInitializeRegistry",
            "NtInitiatePowerAction",
            "NtIsProcessInJob",
            "NtIsSystemResumeAutomatic",
            "NtIsUILanguageComitted",
            "NtListenPort",
            "NtLoadDriver",
            "NtLoadEnclaveData",
            "NtLoadKey",
            "NtLoadKey2",
            "NtLoadKey3",
            "NtLoadKeyEx",
            "NtLockFile",
            "NtLockProductActivationKeys",
            "NtLockRegistryKey",
            "NtLockVirtualMemory",
            "NtMakePermanentObject",
            "NtMakeTemporaryObject",
            "NtManageHotPatch",
            "NtManagePartition",
            "NtMapCMFModule",
            "NtMapUserPhysicalPages",
            "NtMapUserPhysicalPagesScatter",
            "NtMapViewOfSection",
            "NtMapViewOfSectionEx",
            "NtModifyBootEntry",
            "NtModifyDriverEntry",
            "NtNotifyChangeDirectoryFile",
            "NtNotifyChangeDirectoryFileEx",
            "NtNotifyChangeKey",
            "NtNotifyChangeMultipleKeys",
            "NtNotifyChangeSession",
            "NtOpenCpuPartition",
            "NtOpenDirectoryObject",
            "NtOpenEnlistment",
            "NtOpenEvent",
            "NtOpenEventPair",
            "NtOpenFile",
            "NtOpenIoCompletion",
            "NtOpenJobObject",
            "NtOpenKey",
            "NtOpenKeyEx",
            "NtOpenKeyTransacted",
            "NtOpenKeyTransactedEx",
            "NtOpenKeyedEvent",
            "NtOpenMutant",
            "NtOpenObjectAuditAlarm",
            "NtOpenPartition",
            "NtOpenPrivateNamespace",
            "NtOpenProcess",
            "NtOpenProcessToken",
            "NtOpenProcessTokenEx",
            "NtOpenRegistryTransaction",
            "NtOpenResourceManager",
            "NtOpenSection",
            "NtOpenSemaphore",
            "NtOpenSession",
            "NtOpenSymbolicLinkObject",
            "NtOpenThread",
            "NtOpenThreadToken",
            "NtOpenThreadTokenEx",
            "NtOpenTimer",
            "NtOpenTransaction",
            "NtOpenTransactionManager",
            "NtPlugPlayControl",
            "NtPowerInformation",
            "NtPrePrepareComplete",
            "NtPrePrepareEnlistment",
            "NtPrepareComplete",
            "NtPrepareEnlistment",
            "NtPrivilegeCheck",
            "NtPrivilegeObjectAuditAlarm",
            "NtPrivilegedServiceAuditAlarm",
            "NtPropagationComplete",
            "NtPropagationFailed",
            "NtProtectVirtualMemory",
            "NtPssCaptureVaSpaceBulk",
            "NtPulseEvent",
            "NtQueryAttributesFile",
            "NtQueryAuxiliaryCounterFrequency",
            "NtQueryBootEntryOrder",
            "NtQueryBootOptions",
            "NtQueryDebugFilterState",
            "NtQueryDefaultLocale",
            "NtQueryDefaultUILanguage",
            "NtQueryDirectoryFile",
            "NtQueryDirectoryFileEx",
            "NtQueryDirectoryObject",
            "NtQueryDriverEntryOrder",
            "NtQueryEaFile",
            "NtQueryEvent",
            "NtQueryFullAttributesFile",
            "NtQueryInformationAtom",
            "NtQueryInformationByName",
            "NtQueryInformationCpuPartition",
            "NtQueryInformationEnlistment",
            "NtQueryInformationFile",
            "NtQueryInformationJobObject",
            "NtQueryInformationPort",
            "NtQueryInformationProcess",
            "NtQueryInformationResourceManager",
            "NtQueryInformationThread",
            "NtQueryInformationToken",
            "NtQueryInformationTransaction",
            "NtQueryInformationTransactionManager",
            "NtQueryInformationWorkerFactory",
            "NtQueryInstallUILanguage",
            "NtQueryIntervalProfile",
            "NtQueryIoCompletion",
            "NtQueryIoRingCapabilities",
            "NtQueryKey",
            "NtQueryLicenseValue",
            "NtQueryMultipleValueKey",
            "NtQueryMutant",
            "NtQueryObject",
            "NtQueryOpenSubKeys",
            "NtQueryOpenSubKeysEx",
            "NtQueryPerformanceCounter",
            "NtQueryPortInformationProcess",
            "NtQueryQuotaInformationFile",
            "NtQuerySection",
            "NtQuerySecurityAttributesToken",
            "NtQuerySecurityObject",
            "NtQuerySecurityPolicy",
            "NtQuerySemaphore",
            "NtQuerySymbolicLinkObject",
            "NtQuerySystemEnvironmentValue",
            "NtQuerySystemEnvironmentValueEx",
            "NtQuerySystemInformation",
            "NtQuerySystemInformationEx",
            "NtQuerySystemTime",
            "NtQueryTimer",
            "NtQueryTimerResolution",
            "NtQueryValueKey",
            "NtQueryVirtualMemory",
            "NtQueryVolumeInformationFile",
            "NtQueryWnfStateData",
            "NtQueryWnfStateNameInformation",
            "NtQueueApcThread",
            "NtQueueApcThreadEx",
            "NtQueueApcThreadEx2",
            "NtRaiseException",
            "NtRaiseHardError",
            "NtReadFile",
            "NtReadFileScatter",
            "NtReadOnlyEnlistment",
            "NtReadRequestData",
            "NtReadVirtualMemory",
            "NtReadVirtualMemoryEx",
            "NtRecoverEnlistment",
            "NtRecoverResourceManager",
            "NtRecoverTransactionManager",
            "NtRegisterProtocolAddressInformation",
            "NtRegisterThreadTerminatePort",
            "NtReleaseKeyedEvent",
            "NtReleaseMutant",
            "NtReleaseSemaphore",
            "NtReleaseWorkerFactoryWorker",
            "NtRemoveIoCompletion",
            "NtRemoveIoCompletionEx",
            "NtRemoveProcessDebug",
            "NtRenameKey",
            "NtRenameTransactionManager",
            "NtReplaceKey",
            "NtReplacePartitionUnit",
            "NtReplyPort",
            "NtReplyWaitReceivePort",
            "NtReplyWaitReceivePortEx",
            "NtReplyWaitReplyPort",
            "NtRequestPort",
            "NtRequestWaitReplyPort",
            "NtResetEvent",
            "NtResetWriteWatch",
            "NtRestoreKey",
            "NtResumeProcess",
            "NtResumeThread",
            "NtRevertContainerImpersonation",
            "NtRollbackComplete",
            "NtRollbackEnlistment",
            "NtRollbackRegistryTransaction",
            "NtRollbackTransaction",
            "NtRollforwardTransactionManager",
            "NtSaveKey",
            "NtSaveKeyEx",
            "NtSaveMergedKeys",
            "NtSecureConnectPort",
            "NtSerializeBoot",
            "NtSetBootEntryOrder",
            "NtSetBootOptions",
            "NtSetCachedSigningLevel",
            "NtSetCachedSigningLevel2",
            "NtSetContextThread",
            "NtSetDebugFilterState",
            "NtSetDefaultHardErrorPort",
            "NtSetDefaultLocale",
            "NtSetDefaultUILanguage",
            "NtSetDriverEntryOrder",
            "NtSetEaFile",
            "NtSetEvent",
            "NtSetEventBoostPriority",
            "NtSetHighEventPair",
            "NtSetHighWaitLowEventPair",
            "NtSetIRTimer",
            "NtSetInformationCpuPartition",
            "NtSetInformationDebugObject",
            "NtSetInformationEnlistment",
            "NtSetInformationFile",
            "NtSetInformationIoRing",
            "NtSetInformationJobObject",
            "NtSetInformationKey",
            "NtSetInformationObject",
            "NtSetInformationProcess",
            "NtSetInformationResourceManager",
            "NtSetInformationSymbolicLink",
            "NtSetInformationThread",
            "NtSetInformationToken",
            "NtSetInformationTransaction",
            "NtSetInformationTransactionManager",
            "NtSetInformationVirtualMemory",
            "NtSetInformationWorkerFactory",
            "NtSetIntervalProfile",
            "NtSetIoCompletion",
            "NtSetIoCompletionEx",
            "NtSetLdtEntries",
            "NtSetLowEventPair",
            "NtSetLowWaitHighEventPair",
            "NtSetQuotaInformationFile",
            "NtSetSecurityObject",
            "NtSetSystemEnvironmentValue",
            "NtSetSystemEnvironmentValueEx",
            "NtSetSystemInformation",
            "NtSetSystemPowerState",
            "NtSetSystemTime",
            "NtSetThreadExecutionState",
            "NtSetTimer",
            "NtSetTimer2",
            "NtSetTimerEx",
            "NtSetTimerResolution",
            "NtSetUuidSeed",
            "NtSetValueKey",
            "NtSetVolumeInformationFile",
            "NtSetWnfProcessNotificationEvent",
            "NtShutdownSystem",
            "NtShutdownWorkerFactory",
            "NtSignalAndWaitForSingleObject",
            "NtSinglePhaseReject",
            "NtStartProfile",
            "NtStopProfile",
            "NtSubmitIoRing",
            "NtSubscribeWnfStateChange",
            "NtSuspendProcess",
            "NtSuspendThread",
            "NtSystemDebugControl",
            "NtTerminateEnclave",
            "NtTerminateJobObject",
            "NtTerminateProcess",
            "NtTerminateThread",
            "NtTestAlert",
            "NtThawRegistry",
            "NtThawTransactions",
            "NtTraceControl",
            "NtTraceEvent",
            "NtTranslateFilePath",
            "NtUmsThreadYield",
            "NtUnloadDriver",
            "NtUnloadKey",
            "NtUnloadKey2",
            "NtUnloadKeyEx",
            "NtUnlockFile",
            "NtUnlockVirtualMemory",
            "NtUnmapViewOfSection",
            "NtUnmapViewOfSectionEx",
            "NtUnsubscribeWnfStateChange",
            "NtUpdateWnfStateData",
            "NtVdmControl",
            "NtWaitForAlertByThreadId",
            "NtWaitForDebugEvent",
            "NtWaitForKeyedEvent",
            "NtWaitForMultipleObjects",
            "NtWaitForMultipleObjects32",
            "NtWaitForSingleObject",
            "NtWaitForWorkViaWorkerFactory",
            "NtWaitHighEventPair",
            "NtWaitLowEventPair",
            "NtWorkerFactoryWorkerReady",
            "NtWriteFile",
            "NtWriteFileGather",
            "NtWriteRequestData",
            "NtWriteVirtualMemory",
            "NtYieldExecution",
            "NtdllDefWindowProc_A",
            "NtdllDefWindowProc_W",
            "NtdllDialogWndProc_A",
            "NtdllDialogWndProc_W",
        ],
    },
    "kernel32": {"name": "kernel32.dll", "functions": []},
    "kernelbase": {"name": "kernelbase.dll", "functions": []},
    "user32": {"name": "user32.dll", "functions": []},
    "gdi32": {"name": "gdi32.dll", "functions": []},
    "shell32": {"name": "shell32.dll", "functions": []},
    "nsi": {"name": "nsi.dll", "functions": []},
    "shlwapi": {"name": "shlwapi.dll", "functions": []},
    "ole32": {"name": "ole32.dll", "functions": []},
    "combase": {"name": "combase.dll", "functions": []},
    "imm32": {"name": "imm32.dll", "functions": []},
    "msvcrt": {"name": "msvcrt.dll", "functions": []},
    "oleaut32": {"name": "oleaut32.dll", "functions": []},
    "shcore": {"name": "SHCore.dll", "functions": []},
    "sechost": {"name": "sechost.dll", "functions": []},
    "setupapi": {"name": "setupapi.dll", "functions": []},
    "advapi32": {"name": "advapi32.dll", "functions": []},
    "clbcatq": {"name": "clbcatq.dll", "functions": []},
    "ws2_32": {"name": "ws2_32.dll", "functions": []},
    "rpcrt4": {"name": "rpcrt4.dll", "functions": []},
    "msctf": {"name": "msctf.dll", "functions": []},
    "imagehlp": {"name": "imagehlp.dll", "functions": []},
    "crypt32": {"name": "crypt32.dll", "functions": []},
    "ucrtbase": {"name": "ucrtbase.dll", "functions": []},
    "msvcp_win": {"name": "msvcp_win.dll", "functions": []},
    "bcryptprimitives": {"name": "bcryptprimitives.dll", "functions": []},
    "wintypes": {"name": "WinTypes.dll", "functions": []},
    "gdi32full": {"name": "gdi32full.dll", "functions": []},
    "wintrust": {"name": "wintrust.dll", "functions": []},
    "win32u": {"name": "win32u.dll", "functions": []},
    "profapi": {"name": "profapi.dll", "functions": []},
    "cfgmgr32": {"name": "cfgmgr32.dll", "functions": []},
    "devobj": {"name": "devobj.dll", "functions": []},
    "bcrypt": {"name": "bcrypt.dll", "functions": []},
    "ncrypt": {"name": "ncrypt.dll", "functions": []},
    "ntasn1": {"name": "ntasn1.dll", "functions": []},
    "wldp": {"name": "wldp.dll", "functions": []},
    "msasn1": {"name": "msasn1.dll", "functions": []},
    "cryptbase": {"name": "cryptbase.dll", "functions": []},
    "cryptsp": {"name": "cryptsp.dll", "functions": []},
    "userenv": {"name": "userenv.dll", "functions": []},
    "mswsock": {"name": "mswsock.dll", "functions": []},
    "sspicli": {"name": "sspicli.dll", "functions": []},
    "ntmarta": {"name": "ntmarta.dll", "functions": []},
    "kernel.appcore": {"name": "kernel.appcore.dll", "functions": []},
    "rsaenh": {"name": "rsaenh.dll", "functions": []},
    "schannel": {"name": "schannel.dll", "functions": []},
    "powrprof": {"name": "powrprof.dll", "functions": []},
    "umpdc": {"name": "umpdc.dll", "functions": []},
    "dnsapi": {"name": "dnsapi.dll", "functions": []},
    "iphlpapi": {"name": "IPHLPAPI.DLL", "functions": []},
    "winsta": {"name": "winsta.dll", "functions": []},
    "windows.storage": {"name": "windows.storage.dll", "functions": []},
    "dxgi": {"name": "dxgi.dll", "functions": []},
    "d3d11": {"name": "d3d11.dll", "functions": []},
    "directxdatabasehelper": {"name": "directxdatabasehelper.dll", "functions": []},
    "dxcore": {"name": "DXCore.dll", "functions": []},
    "propsys": {"name": "propsys.dll", "functions": []},
    "winmm": {"name": "winmm.dll", "functions": []},
    "resourcepolicyclient": {"name": "ResourcePolicyClient.dll", "functions": []},
    "dwmapi": {"name": "dwmapi.dll", "functions": []},
    "uxtheme": {"name": "uxtheme.dll", "functions": []},
    "apphelp": {"name": "apphelp.dll", "functions": []},
    "wtsapi32": {"name": "wtsapi32.dll", "functions": []},
    "secur32": {"name": "secur32.dll", "functions": []},
    "dcomp": {"name": "dcomp.dll", "functions": []},
    "microsoft.internal.warppal": {
        "name": "Microsoft.Internal.WarpPal.dll",
        "functions": [],
    },
    "fwpuclnt": {"name": "FWPUCLNT.DLL", "functions": []},
    "dhcpcsvc6": {"name": "dhcpcsvc6.dll", "functions": []},
    "dhcpcsvc": {"name": "dhcpcsvc.dll", "functions": []},
    "igd10um64xe": {"name": "igd10um64xe.dll", "functions": []},
    "winhttp": {"name": "winhttp.dll", "functions": []},
    "intelcontrollib": {"name": "IntelControlLib.dll", "functions": []},
    "mmdevapi": {"name": "MMDevAPI.dll", "functions": []},
    "rasadhlp": {"name": "rasadhlp.dll", "functions": []},
    "mscms": {"name": "mscms.dll", "functions": []},
    "version": {"name": "version.dll", "functions": []},
    "twinapi.appcore": {"name": "twinapi.appcore.dll", "functions": []},
    "onecoreuapcommonproxystub": {
        "name": "OneCoreUAPCommonProxyStub.dll",
        "functions": [],
    },
    "cryptnet": {"name": "cryptnet.dll", "functions": []},
    "drvstore": {"name": "drvstore.dll", "functions": []},
    "wdmaud": {"name": "wdmaud.drv", "functions": []},
    "msacm32": {"name": "msacm32.drv", "functions": []},
    "midimap": {"name": "midimap.dll", "functions": []},
    "nvapi64": {"name": "nvapi64.dll", "functions": []},
    "textinputframework": {"name": "TextInputFramework.dll", "functions": []},
    "winmmbase": {"name": "winmmbase.dll", "functions": []},
    "vcruntime140_1": {"name": "vcruntime140_1.dll", "functions": []},
    "nvmessagebus": {"name": "NvMessageBus.dll", "functions": []},
    "vcruntime140": {"name": "vcruntime140.dll", "functions": []},
    "rdpendp": {"name": "rdpendp.dll", "functions": []},
    "comctl32": {"name": "comctl32.dll", "functions": []},
    "msvcp140": {"name": "msvcp140.dll", "functions": []},
    "audioses": {"name": "AudioSes.dll", "functions": []},
    "onecorecommonproxystub": {"name": "OneCoreCommonProxyStub.dll", "functions": []},
    "d3d12": {"name": "D3D12.dll", "functions": []},
    "ncryptsslp": {"name": "ncryptsslp.dll", "functions": []},
    "nvldumdx": {"name": "nvldumdx.dll", "functions": []},
    "nvgpucomp64": {"name": "nvgpucomp64.dll", "functions": []},
    "actxprxy": {"name": "actxprxy.dll", "functions": []},
    "nvwgf2umx": {"name": "nvwgf2umx.dll", "functions": []},
    "nviewh64": {"name": "nviewH64.dll", "functions": []},
    "libxell": {"name": "libxell.dll", "functions": []},
    "d3dscache": {"name": "D3DSCache.dll", "functions": []},
    "d3d12core": {"name": "D3D12Core.dll", "functions": []},
    "icm32": {"name": "icm32.dll", "functions": []},
    "wow.exe": {"name": "Wow.exe", "functions": []},
    "directxapps.sdb": {"name": "DirectXApps.sdb", "functions": []},
    "sortdefault.nls": {"name": "SortDefault.nls", "functions": []},
    "shmem": {"name": "shmem", "functions": []},
    "mswsock.dll.mui": {"name": "mswsock.dll.mui", "functions": []},
    "locale.nls": {"name": "locale.nls", "functions": []},
    "c_437.nls": {"name": "C_437.NLS", "functions": []},
    "c_1252.nls": {"name": "C_1252.NLS", "functions": []},
    "l_intl.nls": {"name": "l_intl.nls", "functions": []},
    "crypt32.dll.mui": {"name": "crypt32.dll.mui", "functions": []},
    "user32.dll.mui": {"name": "user32.dll.mui", "functions": []},
}


# --- API Database Conversion ---
def convert_api_database(api_db):
    """
    Convert all string values in the API database to our simulated UNICODE_STRING.
    The DLL "name" and each function name are converted.
    """
    new_db = {}
    for key, info in api_db.items():
        new_info = {}
        new_info["name"] = info["name"].encode("utf-16le")
        new_info["functions"] = [func.encode("ascii") for func in info["functions"]]
        new_db[key] = new_info
    return new_db


apidb = convert_api_database(api_database)


def fnv1a_32(byte_sequence: bytes, lower=True) -> int:
    fnv_prime = 0x01000193
    h = 0x811C9DC5  # FNV1a offset basis
    data_length = len(byte_sequence)
    for byte_val in byte_sequence[:data_length]:
        # Lowercase the byte value itself
        final_byte = byte_val | 0x20 if lower else byte_val
        h = h ^ final_byte
        h = (h * fnv_prime) & 0xFFFFFFFF  # Keep it 32 bits
    return h


def fnv1a_64(byte_sequence: bytes, lower=True) -> int:
    fnv_prime = 0x100000001B3
    h = 0xCBF29CE484222325  # FNV1a offset basis
    data_length = len(byte_sequence)
    for byte_val in byte_sequence[:data_length]:
        # Lowercase the byte value itself
        final_byte = byte_val | 0x20 if lower else byte_val
        h = h ^ final_byte
        h = (h * fnv_prime) & 0xFFFFFFFFFFFFFFFF  # Keep it 64 bits
    return h


def decode_name(byte_sequence: bytes, is_function=False) -> str:
    """
    Decode a byte sequence to a string. DLL names are UTF-16LE, functions are ASCII.
    """
    try:
        if is_function:
            return byte_sequence.decode("ascii", errors="ignore")
        else:
            # original_name = name_bytes[: len(name_bytes)].decode(
            #     "utf-16le", errors="ignore"
            # )
            return byte_sequence.decode("utf-16le", errors="ignore")
    except:
        return "[cannot decode name]"


def find_name_by_hash(target_hash, hash_function=fnv1a_32):
    """
    Find a DLL or function name matching the target hash in the static database.
    """
    for key, info in apidb.items():
        # Check DLL name (UTF-16LE)
        dll_name_bytes = info["name"]
        if hash_function(dll_name_bytes) == target_hash:
            return f"DLL: {key} ({decode_name(dll_name_bytes)}) found for hash: {target_hash:#010x}"
        # Check functions (ASCII)
        for func_bytes in info["functions"]:
            if hash_function(func_bytes) == target_hash:
                return f"Function in {key}: {decode_name(func_bytes, is_function=True)} found for hash: {target_hash:#010x}"
    return None


def print_hash_table(apidb, debug=False):
    """
    Print a hash table for all DLLs and functions in the database.
    """
    if not debug:
        return
    print("API Hash Lookup Table (32-bit and 64-bit):")
    print("-" * 80)
    for dll, info in apidb.items():
        dll_name_bytes = info["name"]
        hash32 = fnv1a_32(dll_name_bytes)
        hash64 = fnv1a_64(dll_name_bytes)
        print(f"\n{dll}:")
        print(f"  DLL Name: {decode_name(dll_name_bytes)}")
        print(f"    32-bit: 0x{hash32:08X}")
        print(f"    64-bit: 0x{hash64:016X}")
        for func_bytes in info["functions"]:
            func_name = decode_name(func_bytes, is_function=True)
            hash32 = fnv1a_32(func_bytes)
            hash64 = fnv1a_64(func_bytes)
            print(f"  Function: {func_name}")
            print(f"    32-bit: 0x{hash32:08X}")
            print(f"    64-bit: 0x{hash64:016X}")


def find_pid_by_window_name(window_name):
    """
    Find the PID of a process owning a window with the given name.
    """

    def enum_windows_callback(hwnd, results):
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd)
            if window_name.lower() in title.lower():
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                results.append(pid)

    results = []
    win32gui.EnumWindows(enum_windows_callback, results)
    return results[0] if results else None


def get_module_paths(pid):
    """
    Get the file paths of all modules loaded in the process.
    """
    try:
        process_handle = win32api.OpenProcess(
            win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid
        )
        modules = win32process.EnumProcessModulesEx(
            process_handle, win32process.LIST_MODULES_ALL
        )
        paths = []
        for module in modules:
            try:
                path = win32process.GetModuleFileNameEx(process_handle, module)
                paths.append(path)
            except:
                continue
        win32api.CloseHandle(process_handle)
        return paths
    except Exception as e:
        print(f"Error enumerating modules for PID {pid}: {e}")
        return []


def dump_exports(pid):
    """
    Dump exported function names from all modules in the process.
    """
    module_paths = get_module_paths(pid)
    if not module_paths:
        print(f"No modules found for PID {pid}")
        return
    print(f"\nDumping exports for PID {pid}:")
    print("-" * 80)
    for path in module_paths:
        try:
            pe = pefile.PE(path)
            if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                continue
            dll_name = path.split("\\")[-1].lower()
            print(f"\nModule: {dll_name}")
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    func_name = exp.name.decode("ascii", errors="ignore")
                    func_hash = fnv1a_32(func_name.encode("ascii"))
                    print(f"  Function: {func_name} (Hash: 0x{func_hash:08X})")
        except Exception as e:
            print(f"Error processing {path}: {e}")


def generate_enum_output(db):
    print("enum Fnv32aApiHashes")
    print("{")
    # Print DLL entries with comments
    for key, info in db.items():
        dll_hash = fnv1a_32(info["name"])
        dll_name_str = decode_name(info["name"], is_function=False)
        print(f"    FNV32A_{key} = 0x{dll_hash:08X}, // {dll_name_str}")
    print("")  # Blank line separator
    # Print function entries without comments
    for key, info in db.items():
        for func_bytes in info["functions"]:
            func_hash = fnv1a_32(func_bytes)
            func_name_str = decode_name(func_bytes, is_function=True)
            print(f"    FNV32A_{key}_{func_name_str} = 0x{func_hash:08X},")
    print("};")


def main():
    parser = argparse.ArgumentParser(description="API Hash and Export Dumper")
    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Operation mode"
    )

    # 'find' subcommand: Find a name by hash in the static database
    find_parser = subparsers.add_parser("find", help="Find a name by its hash")
    find_parser.add_argument(
        "hash", type=lambda x: int(x, 0), help="Hash value (e.g., 0x12345678)"
    )

    # 'list-hashes' subcommand: List all hashes in the static database
    subparsers.add_parser("list-hashes", help="List all hashes in the static database")
    dev_mode_parser = subparsers.add_parser(
        "dev-mode", help="Run lookups hashes in def target_hashes() function"
    )
    dev_mode_parser.add_argument(
        "--hash",
        choices=["fnv32", "fnv64"],
        help="Target hashes to lookup",
        default="fnv32",
    )

    # 'dump' subcommand: Dump exports from a process
    dump_parser = subparsers.add_parser("dump", help="Dump exports from a process")
    dump_group = dump_parser.add_mutually_exclusive_group(required=True)
    dump_group.add_argument("--pid", type=int, help="Process ID")
    dump_group.add_argument("--window", type=str, help="Window name substring")

    args = parser.parse_args()

    if args.command == "find":
        result = find_name_by_hash(args.hash)
        if result:
            print(f"Found: {result}")
        else:
            print(f"No name found for hash {args.hash:#010x}")
    elif args.command == "list-hashes":
        print_hash_table(apidb, debug=True)
        generate_enum_output(apidb)
    elif args.command == "dump":
        import pefile
        import win32api
        import win32con
        import win32gui
        import win32process

        if args.pid:
            pid = args.pid
        else:
            pid = find_pid_by_window_name(args.window)
            if not pid:
                print(f"No visible window found with name containing: {args.window}")
                sys.exit(1)
        dump_exports(pid)
    elif args.command == "dev-mode":
        if args.hash == "fnv32":
            for target_hash in [
                0x0F42198D,  # kernel32.dll
                0xEFACCA19,  # ntdll.dll
                0x5D756A21,  # NtQueryInformationThread
                0xE049C205,  # NtClose
                0xC1BE16A6,  # NtProtectVirtualMemory
                0x97085561,  # NtSetInformationThread
                0x57F739B7,  # NtDuplicateObject
            ]:
                result = find_name_by_hash(
                    target_hash=target_hash, hash_function=fnv1a_32
                )
                if not result:
                    print(
                        f"Module with hash {target_hash:#010x} not found in the simulated list."
                    )
                else:
                    print(result)
        elif args.hash == "fnv64":
            for target_hash in [
                0xE14B18A7ACF9C443,
                0xA8F42DD374017C56,
                0xACD80F50F7102617,
                0xBB7BB9A74C2F14FB,
            ]:  # kernel32.dll
                result = find_name_by_hash(
                    target_hash=target_hash, hash_function=fnv1a_64
                )
                if not result:
                    print(
                        f"Module with hash {target_hash:#010x} not found in the simulated list."
                    )
                else:
                    print(result)
        else:
            # Verify hash calculation for ntdll.dll using the assembly's method
            ntdll_bytes = apidb["ntdll"]["name"]
            ntdll_hash_variant = fnv1a_32(ntdll_bytes)
            print(
                f"\nVerification: Hash for 'ntdll.dll' using assembly variant: {ntdll_hash_variant:#010x}"
            )
            print(
                f"Target hash from assembly constant calculation:             {0x0F42198D:#010x}"
            )
        # print_hash_table(apidb, debug=True)


if __name__ == "__main__":
    main()
