@ stdcall NtDisplayString(ptr)
@ stdcall NtLoadDriver(ptr)
@ stdcall NtDisplayStringA(ptr)
@ stdcall NtLoadDriverA(ptr)
@ stdcall NtCreateFile(ptr long ptr ptr long long long ptr long long ptr)
@ stdcall NtOpenFile(ptr long ptr ptr long long)
@ stdcall NtReadFile(long long ptr ptr ptr ptr long ptr ptr)
@ stdcall NtWriteFile(long long ptr ptr ptr ptr long ptr ptr)
@ stdcall NtDeleteFile(ptr)
@ stdcall NtSetInformationFile(ptr ptr ptr long long)
@ stdcall NtDeviceIoControlFile(long long long long long long long long long long)
@ stdcall NtFsControlFile(long long long long long long long long long long)
@ stdcall NtQueryDirectoryFile(long long ptr ptr ptr ptr long long long ptr long)
@ stdcall NtQueryInformationFile(ptr ptr ptr long long)
@ stdcall NtQueryAttributesFile(ptr ptr)
@ stdcall NtFlushBuffersFile(long ptr)
@ stdcall NtTerminateThread(ptr long)
@ stdcall NtTerminateProcess(ptr long)
@ stdcall NtResumeThread(long long)
@ stdcall NtAllocateVirtualMemory(long ptr ptr ptr long long)
@ stdcall NtFreeVirtualMemory(long ptr ptr long)
@ stdcall NtCreateSection(ptr long ptr ptr long long ptr)
@ stdcall NtMapViewOfSection(long long ptr long long ptr ptr long long long)
@ stdcall NtUnmapViewOfSection(long ptr)
@ stdcall NtQuerySection (long long long long long)
@ stdcall NtCreateTimer(ptr long ptr long)
@ stdcall NtSetTimer(long ptr ptr ptr long long ptr)
@ stdcall NtWaitForSingleObject(long long long)
@ stdcall NtCreateEvent(long long long long long)
@ stdcall NtSetEvent(ptr ptr)
@ stdcall NtResetEvent(ptr ptr)
@ stdcall NtClearEvent(ptr)
@ stdcall NtClose(long)
@ stdcall NtQuerySystemTime(ptr)
@ stdcall NtQuerySystemInformation(long long long long)
@ stdcall NtShutdownSystem(long)
@ stdcall NtQueryDefaultLocale(long ptr)
@ stdcall NtSetDefaultLocale(long long)
@ stdcall NtDelayExecution(long ptr)
@ stdcall NtOpenKey(ptr long ptr)
@ stdcall NtCreateKey(ptr long ptr long ptr long long)
@ stdcall NtCreateKeyA(ptr long ptr long ptr long long)
@ stdcall NtDeleteKey(long)
@ stdcall NtQueryValueKey(long long long long long long)
@ stdcall NtSetValueKey(ptr ptr long long ptr long)
@ stdcall NtSetValueKeyA(ptr ptr long long ptr long)
@ stdcall NtDeleteValueKey(long ptr)
@ stdcall NtEnumerateKey(long long long long long long)
@ stdcall NtEnumerateValueKey(long long long long long long)
@ stdcall NtQueryKey(long long ptr long ptr)
@ stdcall NtCreateSymbolicLinkObject(ptr long ptr ptr)
@ stdcall NtCreateSymbolicLinkObjectA(ptr long ptr ptr)
@ stdcall NtPlugPlayInitialize()
@ stdcall NtPlugPlayControl(ptr ptr long)
@ stdcall NtTestAlert()
@ stdcall NtGetCurrentProcessorNumber()
@ stdcall LdrGetProcedureAddress(ptr ptr long ptr)
@ stdcall LdrFindEntryForAddress(ptr ptr)
@ stdcall DbgBreakPoint()
@ varargs DbgPrint(str)
@ varargs DbgPrintEx(long long str)
@ stdcall vDbgPrintEx(long long str ptr)
@ stdcall RtlAssert(ptr ptr long ptr)
@ stdcall RtlCompareMemory(ptr ptr long)
@ stdcall RtlCompareMemoryUlong(ptr long long)
@ stdcall RtlFillMemory(ptr long long)
@ stdcall -arch=i386 RtlFillMemoryUlong(ptr long long)
@ stdcall RtlMoveMemory(ptr ptr long)
@ stdcall RtlZeroMemory(ptr long)
@ stdcall RtlInitializeBitMap(ptr ptr long)
@ stdcall RtlSetBits(ptr long long)
@ stdcall RtlAreBitsSet(ptr long long)
@ stdcall -version=0x600+ RtlTestBit(ptr long)
@ stdcall RtlFindMessage(long long long long ptr)
@ stdcall RtlFormatMessage(ptr long long long long ptr ptr long ptr)
@ stdcall RtlFormatMessageEx(ptr long long long long ptr ptr long ptr long)
@ stdcall RtlGetNtGlobalFlags()
@ stdcall RtlSetLastWin32ErrorAndNtStatusFromNtStatus(long)
@ stdcall RtlNtStatusToDosErrorNoTeb(long)
@ stdcall RtlInitializeSListHead(ptr)
@ stdcall RtlPcToFileHeader(ptr ptr)
@ cdecl -arch=x86_64 RtlRestoreContext(ptr ptr)
@ stdcall RtlInitAnsiString(ptr str)
@ stdcall RtlInitAnsiStringEx(ptr str)
@ stdcall RtlAllocateHeap(ptr long ptr)
@ stdcall RtlFreeHeap(long long long)
@ stdcall RtlRaiseStatus(long)
@ stdcall RtlTimeToTimeFields(long long)
@ stdcall RtlTimeFieldsToTime(ptr ptr)
@ stdcall RtlFreeUnicodeString(ptr)
@ stdcall RtlCreateUnicodeStringFromAsciiz(ptr str)
@ stdcall RtlGetCurrentDirectory_U(long ptr)
@ stdcall RtlSetCurrentDirectory_U(ptr)
@ stdcall RtlSystemTimeToLocalTime(ptr ptr)
@ stdcall RtlLocalTimeToSystemTime(ptr ptr)
@ stdcall RtlDosPathNameToNtPathName_U(wstr ptr ptr ptr)
@ stdcall RtlDosPathNameToNtPathName_U_WithStatus(wstr ptr ptr ptr)
@ stdcall RtlInitUnicodeString(ptr wstr)
@ stdcall RtlInitUnicodeStringEx(ptr wstr)
@ stdcall RtlCreateUnicodeString(ptr wstr)
@ stdcall RtlCreateUnicodeStringFromAsciiz(ptr str)
@ stdcall RtlAppendUnicodeStringToString(ptr ptr)
@ stdcall RtlDuplicateUnicodeString(long ptr ptr)
@ stdcall RtlEqualUnicodeString(ptr ptr long)
@ stdcall RtlCompareUnicodeString (ptr ptr long)
@ stdcall RtlCopyUnicodeString(ptr ptr)
@ stdcall RtlAppendUnicodeToString(ptr wstr)
@ stdcall RtlIntegerToChar(long long long ptr)
@ stdcall RtlIntegerToUnicodeString(long long ptr)
@ stdcall RtlUTF8ToUnicodeN(ptr long ptr ptr long)
@ stdcall RtlUnicodeToUTF8N(ptr long ptr ptr long)
@ stdcall RtlAnsiStringToUnicodeString(ptr ptr long)
@ stdcall RtlAnsiStringToUnicodeSize(ptr)
@ stdcall RtlFreeAnsiString(long)
@ stdcall RtlUnicodeStringToAnsiString(ptr ptr long)
@ stdcall RtlUnicodeStringToAnsiSize(ptr)
@ stdcall RtlxUnicodeStringToAnsiSize(ptr) RtlUnicodeStringToAnsiSize
@ stdcall RtlUnicodeStringToOemString(ptr ptr long)
@ stdcall RtlUnicodeStringToOemSize(ptr)
@ stdcall RtlxUnicodeStringToOemSize(ptr) RtlUnicodeStringToOemSize
@ stdcall RtlOemStringToUnicodeString(ptr ptr long)
@ stdcall RtlOemStringToUnicodeSize(ptr)
@ stdcall RtlxOemStringToUnicodeSize(ptr) RtlOemStringToUnicodeSize
@ stdcall RtlUpcaseUnicodeString(ptr ptr long)
@ stdcall RtlUpcaseUnicodeStringToAnsiString(ptr ptr long)
@ stdcall RtlUpcaseUnicodeStringToCountedOemString(ptr ptr long)
@ stdcall RtlUpcaseUnicodeStringToOemString(ptr ptr long)
@ stdcall RtlDowncaseUnicodeString(ptr ptr long)
@ stdcall RtlGenerate8dot3Name(ptr ptr long ptr)
@ stdcall RtlIsNameLegalDOS8Dot3(ptr ptr ptr)
@ stdcall RtlStringFromGUID(ptr ptr)
@ stdcall RtlAdjustPrivilege(long long long ptr)
@ stdcall RtlCreateProcessParameters(ptr ptr ptr ptr ptr ptr ptr ptr ptr ptr)
@ stdcall RtlCreateUserProcess(ptr long ptr ptr ptr ptr long ptr ptr ptr)
@ stdcall RtlCreateHeap(long ptr long long ptr ptr)
@ stdcall RtlDestroyHeap(long)
@ stdcall RtlQueryRegistryValues(long ptr ptr ptr ptr)
@ stdcall RtlWriteRegistryValue(long ptr ptr long ptr long)
@ stdcall RtlDeleteRegistryValue(long ptr ptr)
@ stdcall RtlFirstEntrySList(ptr)
@ stdcall RtlInterlockedPushEntrySList(ptr ptr)
@ stdcall RtlInterlockedPopEntrySList(ptr)
@ stdcall RtlInterlockedFlushSList(ptr)
@ fastcall RtlInterlockedPushListSList(ptr ptr ptr long)
@ stdcall RtlInitializeRangeList(ptr)
@ stdcall RtlAddRange(ptr long long long long long long ptr ptr)
@ stdcall RtlGetFirstRange(ptr ptr ptr)
@ stdcall RtlCopyRangeList(ptr ptr)
@ stdcall RtlInvertRangeList(ptr ptr)
@ stdcall RtlFindRange(ptr long long long long long long long long ptr ptr ptr)
@ stdcall RtlIsRangeAvailable(ptr long long long long long long ptr ptr ptr)
@ stdcall RtlMergeRangeLists(ptr ptr ptr long)
@ stdcall RtlDeleteRange(ptr long long long long ptr)
@ stdcall RtlDeleteOwnersRanges(ptr ptr)
@ stdcall RtlFreeRangeList(ptr)
@ stdcall RtlGetNtProductType(ptr)
@ stdcall RtlGetNtVersionNumbers(ptr ptr ptr)
@ stdcall RtlGetVersion(ptr)
@ stdcall RtlVerifyVersionInfo(ptr long double)
@ stdcall -ret64 VerSetConditionMask(double long long)
@ cdecl memcmp(ptr ptr long)
@ cdecl memcpy(ptr ptr long)
@ cdecl memmove(ptr ptr long)
@ cdecl memset(ptr long long)
@ cdecl strcat(str str)
@ cdecl strncat(str str long)
@ cdecl strcmp()
@ cdecl strchr(str long)
@ cdecl strstr(str str)
@ cdecl strlen(str)
@ cdecl strnlen(str long)
@ cdecl strncmp(str str long)
@ cdecl strcpy(ptr str)
@ cdecl strncpy(ptr str long)
@ cdecl strspn(str str)
@ cdecl strpbrk(str str)
@ cdecl isprint(long)
@ cdecl isdigit(long)
@ cdecl isxdigit(long)
@ cdecl isspace(long)
@ cdecl tolower(long)
@ cdecl toupper(long)
@ cdecl towlower(long)
@ cdecl towupper(long)
@ cdecl wcslen(wstr)
@ cdecl wcsstr(wstr wstr)
@ cdecl wcschr(wstr long)
@ cdecl wcscpy_s(wstr long wstr)
@ cdecl wcsncpy(ptr wstr long)
@ cdecl wcsncpy_s(wstr long wstr long)
@ cdecl wcscat_s(wstr long wstr)
@ cdecl wcsncat_s(wstr long wstr long)
@ cdecl wcsncmp(wstr wstr long)
@ cdecl _strcmpi(str str) _stricmp
@ cdecl _stricmp(str str)
@ cdecl _strnicmp(str str long)
@ cdecl _vsnprintf(ptr long str ptr) vsnprintf
@ cdecl _vsnwprintf(ptr long wstr ptr)
@ varargs _snprintf(ptr long str) snprintf
@ varargs _snwprintf(ptr long wstr)
@ varargs swprintf(ptr wstr)
@ cdecl -arch=i386 -ret64 _alldiv(double double)
@ cdecl -arch=i386 _alldvrm()
@ cdecl -arch=i386 -ret64 _allmul(double double)
@ cdecl -arch=i386 -ret64 _allrem(double double)
@ cdecl -arch=i386 _allshl()
@ cdecl -arch=i386 _allshr()
@ cdecl -arch=i386 -ret64 _aulldiv(double double)
@ cdecl -arch=i386 _aulldvrm()
@ cdecl -arch=i386 -ret64 _aullrem(double double)
@ cdecl -arch=i386 _aullshr()
@ cdecl -arch=i386 _except_handler3(ptr ptr ptr ptr)
@ cdecl -arch=x86_64 __C_specific_handler(ptr long ptr ptr)
@ cdecl _assert(str str long)
@ cdecl -arch=x86_64 __chkstk()
@ extern -arch=i386 _chkstk
@ extern RtlpDbgTraceModuleName
@ extern KiUserExceptionDispatcher
