// <sys/stat.h> for Windows: mkdir(2) with its mode argument. See src/compat/win32/hw_w32.h.
#ifndef HOLYWISP_COMPAT_SYS_STAT_H
#define HOLYWISP_COMPAT_SYS_STAT_H

// This file stands in front of the toolchain's header of the same name and passes on to it.
#pragma GCC system_header
#include_next <sys/stat.h>

// The mode is ignored: a directory here takes its access list from its parent.
int hw_w32_mkdir(const char *path, int mode);

#ifndef HW_W32_NO_MACROS
#define mkdir(path, mode) hw_w32_mkdir((path), (mode))
#endif

#endif
