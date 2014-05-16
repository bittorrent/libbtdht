#
# Host detection
#

# Symbolic names for HOST variable
HOST_LINUX := Linux
HOST_MAC := Darwin
HOST_CYGWIN1 := CYGWIN_NT-6.1-WOW64
HOST_CYGWIN2 := CYGWIN_NT-6.0
HOST_CYGWIN3 := CYGWIN_NT-5.1
HOST_CYGWIN := CYGWIN
HOST_FREEBSD := FreeBSD

PROC_PPC := powerpc
PROC_i386 := i386

ARCH_x86_64 := x86_64

# HOST can be: Linux, Darwin, CYGWIN_NT-6.0, CYGWIN_NT-5.1
HOST := $(shell uname -s)
PROC := $(shell uname -p)
ARCH := $(shell uname -m)

# Normalize CYGWIN names to just one
ifeq ($(HOST),$(HOST_CYGWIN1))
HOST := $(HOST_CYGWIN)
endif
ifeq ($(HOST),$(HOST_CYGWIN2))
HOST := $(HOST_CYGWIN)
endif
ifeq ($(HOST),$(HOST_CYGWIN3))
HOST := $(HOST_CYGWIN)
endif

