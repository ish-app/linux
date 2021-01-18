#ifndef __ISH_ASM_STRING_H
#define __ISH_ASM_STRING_H

/* These all come from host libc. */

#define __HAVE_ARCH_STRCPY
extern char *strcpy(char *, const char *);

#define __HAVE_ARCH_STRNCPY
extern char *strncpy(char *, const char *, size_t);

#define __HAVE_ARCH_STRCAT
extern char *strcat(char *, const char *);

#define __HAVE_ARCH_STRNCAT
extern char *strncat(char *, const char *, size_t);

#define __HAVE_ARCH_STRCMP
extern int strcmp(const char *, const char *);

#define __HAVE_ARCH_STRNCMP
extern int strncmp(const char *, const char *, size_t);

#define __HAVE_ARCH_STRCHR
extern char *strchr(const char *, int);

#define __HAVE_ARCH_STRRCHR
extern char *strrchr(const char *, int);

#define __HAVE_ARCH_STRLEN
extern size_t strlen(const char *);

#define __HAVE_ARCH_MEMCPY
extern void *memcpy(void *, const void *, size_t);

#define __HAVE_ARCH_MEMMOVE
extern void * memmove(void *, const void *, size_t);

#define __HAVE_ARCH_MEMCHR
extern void * memchr(const void *,int,__kernel_size_t);

#define __HAVE_ARCH_MEMSET
extern void * memset(void *, int, size_t);

#endif
