// SPDX-License-Identifier: MIT
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/Utils/LogManager.h>

#include <atomic>
#include <cstdint>
#include <windef.h>
#include <winbase.h>
#define __WINESRC__
#include <winternl.h>
#include <libloaderapi.h>
#include "FEXUnixLib.h"
#include "Priv.h"

#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0

#define MADV_HUGEPAGE 14
#define MADV_NOHUGEPAGE 15

extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace FEX::Windows::UnixLib {
static bool SupportsVirtualName {true};
unixlib_handle_t UnixLibHandle {};

decltype(__wine_unix_call_dispatcher) UnixCallDispatcher {};

using wine_server_handle_to_fd_t = NTSTATUS(CDECL*)(HANDLE, unsigned int, int*, unsigned int*);
static wine_server_handle_to_fd_t WineServerHandleToFd {};

#ifdef ARCHITECTURE_arm64ec
// On ARM64EC, indirect calls go through __os_arm64x_dispatch_icall which invokes
// FEX's custom call checker. Use a naked trampoline to bypass the dispatch mechanism
// and call the unix dispatcher directly via a register branch.
static decltype(__wine_unix_call_dispatcher) UnixCallDispatcherDirect {};

static NTSTATUS __attribute__((naked)) TrampolineCall(unixlib_handle_t, unsigned int, void*) {
  asm(R"(
  adrp x16, %[Displace];
  ldr x16, [x16, #:lo12:%[Displace]]
  br x16
  )" ::[Displace] "S"(&UnixCallDispatcherDirect)
      : "memory");
}
#endif
bool Init(HMODULE NtDll) {
  const auto Sym = GetProcAddress(NtDll, "__wine_unix_call_dispatcher");
  WineServerHandleToFd = reinterpret_cast<wine_server_handle_to_fd_t>(GetProcAddress(NtDll, "wine_server_handle_to_fd"));

  if (!Sym) {
    return false;
  }

  auto TryNewWineMethod = []() {
#ifdef ARCHITECTURE_arm64ec
    auto Name = InitUnicodeString(L"libarm64ecfex");
#else
    auto Name = InitUnicodeString(L"libwow64fex");
#endif

    // Not supported in Proton at all, but supported in upstream WINE.
    uint64_t Result[2];
    if (NtQueryVirtualMemory(NtCurrentProcess(), &Name, MemoryWineLoadUnixLibByName, Result, sizeof(Result), nullptr)) {
      return false;
    }

    // Result[0] = unixlib_module_t
    // Result[1] = unixlib_handle_t
    // Module is ignored as it's only used to unload.
    UnixLibHandle = Result[1];
    return true;
  };

  auto TryOldWineMethod = []() {
    // Supported in Proton 11 and Experimental (2026-06-26).
    return NtQueryVirtualMemory(NtCurrentProcess(), &__ImageBase, MemoryWineUnixFuncs, &UnixLibHandle, sizeof(UnixLibHandle), nullptr) == 0;
  };

#ifdef FEX_IOS_HOST
  /* iOS-Madeira (FEX-2607 rebase): the new load-by-name unixlib method
   * (TryNewWineMethod) expects a separate "libarm64ecfex" .so unixlib. iOS has
   * no .so files — load_unixlib_by_name dlopen()s a nonexistent path and can
   * return a bogus handle whose funcs table is garbage; the dispatcher then
   * blr's into code bytes (the post-rebase fault storm). The old
   * MemoryWineUnixFuncs-on-__ImageBase path is the one our iOS ntdll-unix
   * actually implements and what ios-port always used. Force it. */
  (void)TryNewWineMethod;
  if (!TryOldWineMethod()) {
    return false;
  }
#else
  if (!TryNewWineMethod() && !TryOldWineMethod()) {
    return false;
  }
#endif

#ifdef ARCHITECTURE_arm64ec
  UnixCallDispatcherDirect = *reinterpret_cast<decltype(__wine_unix_call_dispatcher)*>(Sym);
  UnixCallDispatcher = TrampolineCall;
#else
  UnixCallDispatcher = *reinterpret_cast<decltype(__wine_unix_call_dispatcher)*>(Sym);
#endif

  // Give a log saying that the unix lib was loaded.
  LogMan::Msg::IFmt("FEX: Loaded FEXUnixLib (UnixLibHandle=0x{:x})", static_cast<unsigned long long>(UnixLibHandle));
  return true;
}

bool Available() {
  return UnixLibHandle != 0;
}

bool TryEnableHardwareTSO() {
#ifdef FEX_IOS_HOST
  // iOS: FEX-2607's FEXUnixLib funcs table isn't registered on the iOS unix
  // side, and the legacy Illegal:: paths issue raw Linux syscalls (unsafe on
  // XNU). No-op every entry point; FEX falls back to software TSO, which is
  // correct (our hand-rolled HostFeatures doesn't advertise hardware TSO).
  return false;
#endif
  if (!Available()) {
    return false;
  }

  FEXUnixLib_SetHardwareTSOControlArgs Args {
    .Enable = true,
  };

  return Call(FEXUnixLibFunctions::SetHardwareTSOControl, &Args) == STATUS_SUCCESS;
}

bool SetKernelUnalignedAtomicControl(uint64_t Flags) {
#ifdef FEX_IOS_HOST
  (void)Flags;
  return false;
#endif
  if (!Available()) {
    return false;
  }

  FEXUnixLib_SetKernelUnalignedAtomicControl Args {
    .Flags = Flags,
  };

  return Call(FEXUnixLibFunctions::SetKernelUnalignedAtomicControl, &Args) == STATUS_SUCCESS;
}

void VirtualTHPControl(const void* Ptr, size_t Size, FEXCore::Allocator::THPControl Control) {
#ifdef FEX_IOS_HOST
  (void)Ptr;
  (void)Size;
  (void)Control;
  return;
#endif
  if (!Available()) {
    return;
  }

  FEXUnixLib_Madvise Args {
    .Addr = Ptr,
    .Size = Size,
    .Advise = Control == FEXCore::Allocator::THPControl::Disable ? MADV_NOHUGEPAGE : MADV_HUGEPAGE,
  };

  Call(FEXUnixLibFunctions::Madvise, &Args);
}

void VirtualName(const char* Name, const void* Ptr, size_t Size) {
#ifdef FEX_IOS_HOST
  /* iOS-Madeira ml294 (task #51): PUBLISH FEX'S OWN NAME FOR EVERY HOST ALLOCATION.
   *
   * The prctl/unixlib naming below is meaningless on iOS, so this was a pure no-op --
   * which meant FEX already knew the identity of every region it allocates and we were
   * throwing that away.
   *
   * ml293 established that the recurring bogus guest RIP (<arena>+0xd0080/0xe0080/0xf0080)
   * lands inside FEX's OWN 512MB host reservations, not Chromium's heap: all 23 [bigres]
   * requests carry guest rsp=0/rip=0 (no guest context), two per thread, issued at FEX
   * thread init. ml283 independently showed x28 (the CpuStateFrame pointer) = 0x7c20001140,
   * i.e. a ThreadState living in one of those same arenas.
   *
   * So the question is no longer "what heap is this" but "WHICH FEX STRUCTURE". FEX names
   * them itself -- FEXMem_ThreadState, FEXMem_Lookup, FEXMem_Lookup_L1, FEXMem_CallRetStacks,
   * FEXMemJIT, FEXMem_Misc, FEXMem -- so emit name+range and the bogus RIP can be matched to
   * a named structure offline, with no further device runs.
   *
   * This replaces a no-op, so it cannot change behaviour. Capped so a per-thread allocation
   * pattern cannot storm the log. */
  {
    static std::atomic<uint32_t> NameCount {0};
    if (NameCount.fetch_add(1) < 256) {
      LogMan::Msg::EFmt("[vname] {} {:#x}..{:#x} size={:#x}", Name ? Name : "<null>", reinterpret_cast<uintptr_t>(Ptr),
                        reinterpret_cast<uintptr_t>(Ptr) + Size, Size);
    }
  }
  return;
#endif
  if (!SupportsVirtualName || !Available()) {
    return;
  }

  FEXUnixLib_SetVMAName Args {
    .Addr = Ptr,
    .Size = Size,
    .Name = Name,
  };

  if (Call(FEXUnixLibFunctions::SetVMAName, &Args) != STATUS_SUCCESS) {
    SupportsVirtualName = false;
  }
}

SHMSlotResult AllocateSHMSlots(void* SHMBase, uint32_t MapSize, uint32_t MaxSize) {
#ifdef FEX_IOS_HOST
  (void)SHMBase;
  (void)MapSize;
  (void)MaxSize;
  return {};
#endif
  if (!Available()) {
    return {};
  }

  FEXUnixLib_GetSHMStatsVMA Args {
    .SHMBase = SHMBase,
    .MapSize = MapSize,
    .MaxSize = MaxSize,
  };

  if (Call(FEXUnixLibFunctions::GetSHMStatsVMA, &Args) == STATUS_SUCCESS) {
    return {
      .SHMBase = Args.SHMBase,
      .MappedSize = Args.MapSize,
    };
  }

  return {};
}

void DeleteSHMStatsFile() {
#ifdef FEX_IOS_HOST
  return;
#endif
  if (!Available()) {
    return;
  }

  Call(FEXUnixLibFunctions::DeleteSHMStatsFile, nullptr);
}

void* MapFile(HANDLE FileHandle, uint64_t MapSize) {
#ifdef FEX_IOS_HOST
  // iOS: the unix side registers no FEXUnixLib function table; callers fall back to reading.
  (void)FileHandle;
  (void)MapSize;
  return nullptr;
#endif
  if (Available() && WineServerHandleToFd) {
    FEXUnixLib_MapFile Args {
      .FD = -1,
      .MapSize = MapSize,
    };

    // this is a dup equivalent
    auto Result = WineServerHandleToFd(FileHandle, FILE_READ_DATA, &Args.FD, nullptr);
    if (Result != STATUS_SUCCESS || Args.FD == -1) {
      return nullptr;
    }

    if (Call(FEXUnixLibFunctions::MapFile, &Args) == STATUS_SUCCESS) {
      return Args.Result;
    }
  }

  return nullptr;
}

uint32_t GetPID() {
#ifdef FEX_IOS_HOST
  return GetCurrentProcessId();
#endif
  if (Available()) {
    FEXUnixLib_GetPID Args {};
    Call(FEXUnixLibFunctions::GetPID, &Args);
    return Args.Result;
  }

  return GetCurrentProcessId();
}

} // namespace FEX::Windows::UnixLib
