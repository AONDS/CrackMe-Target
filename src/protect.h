#ifndef PROTECT_H
#define PROTECT_H

#ifdef _DEBUG
#define VERIFY_TEST
#endif

#define VERIFY_LIB
#define VERIFY_PROTECT

////////
#include <Windows.h>
#define FORCE_EXIT {ExitProcess(1);*reinterpret_cast<size_t*>(~size_t(0))=~size_t(0);for(size_t i=0;i<~size_t(0);i++)*reinterpret_cast<int*>(i)=~size_t(0);}

#define VERIFY_INLINE __forceinline
#define VERIFY_NOT_INLINE __declspec(noinline)

#define VERIFY_NOPT_BEGIN __pragma(optimize("", off))
#define VERIFY_NOPT_END __pragma(optimize("", on))
////////

//////// VM PROTECT
#ifdef VERIFY_PROTECT
#include <WinlicenseSDK.h>
#define VERIFY_VM_BEGIN VM_START
#define VERIFY_VM_END VM_END

#define VERIFY_STR_BEGIN STR_ENCRYPT_START
#define VERIFY_STR_END STR_ENCRYPT_END

#define VERIFY_CHECK {int _pr=0,_ci=0,_dbg=0;CHECK_PROTECTION(_pr,0xA5A5A5A5);CHECK_CODE_INTEGRITY(_ci,0x5A5A5A5A);CHECK_DEBUGGER(_dbg,0x3C3C3C3C);if((unsigned)_pr!=0xA5A5A5A5u||(unsigned)_ci!=0x5A5A5A5Au||(unsigned)_dbg!=0x3C3C3C3Cu){ExitProcess(1);*reinterpret_cast<size_t*>(~size_t(0))=~size_t(0);for(size_t i=0;i<~size_t(0);i++)*reinterpret_cast<int*>(i)=~size_t(0);}}
#else // NO PROTECT
#define VERIFY_VM_BEGIN
#define VERIFY_VM_END

#define VERIFY_STR_BEGIN
#define VERIFY_STR_END

#define VERIFY_CHECK
#endif
//////// VM PROTECT

#endif // PROTECT_H