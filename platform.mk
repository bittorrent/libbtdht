#
# Platform Setup
#

PLATFORM_FLAGS = -DPOSIX

ifeq ($(TARGET),$(HOST_MAC))
FWKS=/System/Library/Frameworks
FWKCFLAGS=-I/Developer/Headers/FlatCarbon \
	 -I$(FWKS)/IOKit.framework/Versions/Current/Headers

PLATFORM_FLAGS += $(FWKCFLAGS)
PLATFORM_LDFLAGS += -framework Carbon -framework IOKit
ifeq ($(STRIP_DEAD),yes)
PLATFORM_LDFLAGS += -dead_strip
endif
# Building for 32-bit

ifeq ($(PROC),$(PROC_PPC))
PLATFORM_FLAGS += -arch ppc
PLATFORM_LDFLAGS += -arch ppc
else
ifeq ($(ARCH), $(ARCH_x86_64))
PLATFORM_FLAGS += -arch x86_64
PLATFORM_LDFLAGS += -arch x86_64
else
PLATFORM_FLAGS += -arch i386
PLATFORM_LDFLAGS += -arch i386
endif
endif

ifeq ($(CC), "")
	CC=/usr/bin/gcc
endif

ifeq ($(CXX), "")
	CXX=/usr/bin/g++
endif

STRIP=/usr/bin/strip -x
endif

ifeq ($(TARGET),$(HOST_LINUX))
# -lrt is for clock_gettime() - see its man page
PLATFORM_FLAGS  += -DLINUX
endif

ifeq ($(TARGET),$(HOST_CYGWIN))
PLATFORM_FLAGS += -DCYGWIN
endif

ifeq ($(TARGET),$(HOST_FREEBSD))
PLATFORM_FLAGS += -DFREEBSD
endif

ifeq ($(TARGET),$(TARGET_ANDROID))
PLATFORM_FLAGS += -DLINUX
PLATFORM_FLAGS += -DANDROID
endif


