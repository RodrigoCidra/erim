/*
 * erim_api_inlined.h
 * 
 * Provides interface for switching and initlization of ERIM to be
 * used directly in functions.
 * 
 */

#ifndef ERIM_API_INLINED_H_
#define ERIM_API_INLINED_H_

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Debug prints
 */
#ifdef ERIM_DBG
  #define ERIM_DBM(...)				\
    do {					\
      fprintf(stderr, __VA_ARGS__);		\
      fprintf(stderr, "\n");			\
    } while(0)
#else // disable debug
   #define ERIM_DBM(...)
#endif

/*
 * Error prints
 */
#define ERIM_ERR(...)				\
    do {					\
      fprintf(stderr, __VA_ARGS__);		\
      fprintf(stderr, "\n");			\
    } while(0)
  
#include <stdint.h>
#include "pkeys.h"

#define ERIM_ISOLATED_DOMAIN 0

#define ERIM_TRUSTED_DOMAIN_IDENT_LOC ((void*)(1ull<<44))
#define ERIM_TRUSTED_DOMAIN_IDENT (*(int*)ERIM_TRUSTED_DOMAIN_IDENT_LOC)
#define ERIM_TRUSTED_FLAGS (*((int*)ERIM_TRUSTED_DOMAIN_IDENT_LOC+1))
#define ERIM_PKRU_VALUE_UNTRUSTED (*((int*)ERIM_TRUSTED_DOMAIN_IDENT_LOC+2))
  
#define ERIM_PKRU_ISOTRS_UNTRUSTED_CI (0x5555555C) //1100
#define ERIM_PKRU_ISOTRS_UNTRUSTED_IO (0x55555558)
#define ERIM_PKRU_ISOUTS_UNTRUSTED_CI (0x55555553) //0011
#define ERIM_PKRU_ISOUTS_UNTRUSTED_IO (0x55555552)


// trusted -> domain 0, untrusted -> domain 1
#define ERIM_TRUSTED_DOMAIN 0
  #ifdef ERIM_INTEGRITY_ONLY
    // read(trusted = allowed, write(trusted) = disallowed
    #define ERIM_UNTRUSTED_PKRU ERIM_PKRU_ISOUTS_UNTRUSTED_IO
  #else
    // read(trusted = write(trusted) = disallowed
    #define ERIM_UNTRUSTED_PKRU ERIM_PKRU_ISOUTS_UNTRUSTED_CI
  #endif

#define ERIM_TRUSTED_PKRU (0x55555550)

//   pkru   - 15|14|13|12|11|10|09|08|07|06|05|04|03|02|01|00
//===========================================================
// 00000000 - 00|00|00|00|00|00|00|00|00|00|00|00|00|00|00|00 PKRU Monitor (access to all domains)
// 55555551 - 01|01|01|01|01|01|01|01|01|01|01|01|01|01|00|01
// 55555545 - 01|01|01|01|01|01|01|01|01|01|01|01|01|00|01|01
// 55555515 - 01|01|01|01|01|01|01|01|01|01|01|01|00|01|01|01
// 55555455 - 01|01|01|01|01|01|01|01|01|01|01|00|01|01|01|01
// 55555151 - 01|01|01|01|01|01|01|01|01|01|00|01|01|01|01|01
// 55554551 - 01|01|01|01|01|01|01|01|01|00|01|01|01|01|01|01
// 55551551 - 01|01|01|01|01|01|01|01|00|01|01|01|01|01|01|01
// 55545551 - 01|01|01|01|01|01|01|00|01|01|01|01|01|01|01|01
// 55515551 - 01|01|01|01|01|01|00|01|01|01|01|01|01|01|01|01
// 55455551 - 01|01|01|01|01|00|01|01|01|01|01|01|01|01|01|01
// 55155551 - 01|01|01|01|00|01|01|01|01|01|01|01|01|01|01|01
// 54555551 - 01|01|01|00|01|01|01|01|01|01|01|01|01|01|01|01
// 51555551 - 01|01|00|01|01|01|01|01|01|01|01|01|01|01|01|01
// 45555551 - 01|00|01|01|01|01|01|01|01|01|01|01|01|01|01|01
// 15555551 - 00|01|01|01|01|01|01|01|01|01|01|01|01|01|01|01
#define ERIM_DOMAIN(domain) (\
    (domain == 1) ? 0x55555551 : \
    (domain == 2) ? 0x55555545 : \
    (domain == 3) ? 0x55555515 : \
    (domain == 4) ? 0x55555455 : \
    (domain == 5) ? 0x55555155 : \
    (domain == 6) ? 0x55554555 : \
    (domain == 7) ? 0x55551555 : \
    (domain == 8) ? 0x55545555 : \
    (domain == 9) ? 0x55515555 : \
    (domain == 10) ? 0x55455555 : \
    (domain == 11) ? 0x55155555 : \
    (domain == 12) ? 0x54555555 : \
    (domain == 13) ? 0x51555555 : \
    (domain == 14) ? 0x45555555 : \
    (domain == 15) ? 0x15555555 : \
    0 \
)
// Get currently executing domain
#define ERIM_EXEC_DOMAIN(pkru) (\
    (pkru == 0x55555551) ? 1 : \
    (pkru == 0x55555545) ? 2 : \
    (pkru == 0x55555515) ? 3 : \
    (pkru == 0x55555455) ? 4 : \
    (pkru == 0x55555155) ? 5 : \
    (pkru == 0x55554555) ? 6 : \
    (pkru == 0x55551555) ? 7 : \
    (pkru == 0x55545555) ? 8 : \
    (pkru == 0x55515555) ? 9 : \
    (pkru == 0x55455555) ? 10 : \
    (pkru == 0x55155555) ? 11 : \
    (pkru == 0x54555555) ? 12 : \
    (pkru == 0x51555555) ? 13 : \
    (pkru == 0x45555555) ? 14 : \
    (pkru == 0x15555555) ? 15 : \
    0 \
)

// Accessing stack values
#define erim_get_stackptr(ptr)				\
  do {							\
    asm volatile("movq %%rsp, %0" : "+m" (ptr));	\
  } while(0)


// Switching between stacks
#define ERIM_DOMAIN_STACK_LOC(domain) ((void*)(11ull<<(44 - domain)))

#define ERIM_SWITCH_STACK(stackLoc, regularLoc)					\
  do {									\
    erim_get_stackptr(regularLoc);					\
    char * ERIM_ISOLATED_STACK = (char*) stackLoc;       \
    memcpy(ERIM_ISOLATED_STACK, regularLoc, 1024);		\
    asm volatile("movq %0, %%rsp\n" : "=m" (ERIM_ISOLATED_STACK));	\
  } while(0)

#define ERIM_SWITCH_BACK(regularLoc)					\
  do {									\
    asm volatile("movq %0, %%rsp\n" : "=m" (regularLoc));	\
  } while(0)
  
#define ERIM_SWITCH_TO_TRUSTED_STACK 
#define ERIM_SWITCH_TO_UNTRUSTED_STACK 
  
  
// Switching between isolated and application
#define erim_switch_to_trusted						\
  do {                                                                  \
    __wrpkru(ERIM_TRUSTED_PKRU);					\
    ERIM_SWITCH_TO_TRUSTED_STACK;					\
    ERIM_DBM("pkru: %x", __rdpkru());					\
    ERIM_INCR_CNT(1);							\
  } while(0)
  
#define erim_switch_to_untrusted					\
  do {                                                                  \
    ERIM_SWITCH_TO_UNTRUSTED_STACK;					\
    __wrpkrucheck(ERIM_UNTRUSTED_PKRU);					\
    ERIM_DBM("pkru: %x", __rdpkru());					\
    ERIM_INCR_CNT(1);							\
  } while(0)    
  
  // switch to untrustd based on trusted flags
#define erim_switch_to_untrusted_flags					\
  do {									\
    if(ERIM_TRUSTED_DOMAIN_IDENT == 1){					\
      ERIM_SWITCH_TO_REGULAR_STACK;					\
    } else {								\
      ERIM_SWITCH_TO_ISOLATED_STACK;					\
    }									\
    __wrpkrumem(ERIM_PKRU_VALUE_UNTRUSTED);				\
    ERIM_DBM("pkru: %s", __rdpkru());					\
    ERIM_INCR_CNT(1);							\
  } while(0)

  // switch to untrustd based on trusted flags
#define erim_switch_to_trusted_flags					\
  do {									\
    __wrpkru(ERIM_TRUSTED_PKRU);					\
    if(ERIM_TRUSTED_DOMAIN_IDENT == 1) {				\
      ERIM_SWITCH_TO_ISOLATED_STACK;					\
    } else {								\
      ERIM_SWITCH_TO_REGULAR_STACK;					\
    }									\
    ERIM_DBM("pkru: %s", __rdpkru());					\
    ERIM_INCR_CNT(1);							\
  } while(0)
  
#define uint8ptr(ptr) ((uint8_t *)ptr)
  
#define erim_isWRPKRU(ptr)				\
  ((uint8ptr(ptr)[0] == 0x0f && uint8ptr(ptr)[1] == 0x01	\
   && uint8ptr(ptr)[2] == 0xef)?			\
  1 : 0)

#define erim_isXRSTOR(ptr) \
   ((uint8ptr(ptr)[0] == 0x0f && uint8ptr(ptr)[1] == 0xae \
    && (uint8ptr(ptr)[2] & 0xC0) != 0xC0 \
    && (uint8ptr(ptr)[2] & 0x38) == 0x28) ? 1 : 0)
  
#ifdef __cplusplus
}
#endif
 
#endif
