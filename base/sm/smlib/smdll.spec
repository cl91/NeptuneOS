@ stdcall SmConnectToSm(ptr ptr long ptr)
@ stdcall SmSessionComplete(ptr long long)
@ stdcall SmExecPgm(ptr ptr long)
@ stdcall SmSendMsgToSm(ptr ptr)
@ stdcall SmLoadDeferedSubsystem(ptr ptr)
@ stdcall SmStartCsr(ptr ptr ptr ptr ptr)
@ stdcall SmStopCsr(ptr long)

# Utilities
@ stdcall SmExecuteProgram(ptr ptr)
@ stdcall SmLookupSubsystem(ptr ptr ptr ptr ptr)
@ stdcall SmQueryInformation(ptr long ptr long ptr)
