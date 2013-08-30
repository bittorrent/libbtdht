ACLOCAL_AMFLAGS = -I m4

CC = clang -std=c99
CXX = clang++
LD = clang++

SUBDIRS = ut_utils .

BASE_CFLAGS = -Wall -DPOSIX -D_UNICODE -D_LIB

if DEBUG
BASE_CFLAGS += -D_DEBUG -g -O0
else
BASE_CFLAGS += -DNDEBUG -O2
endif

AM_CFLAGS = $(BASE_CFLAGS)								\
            -I$(top_srcdir)/ut_utils/src				\
            -I$(top_srcdir)/libtomcrypt/src/headers		\
            -I$(top_srcdir)/libtommath/src/headers

AM_CXXFLAGS = -std=c++11 $(AM_CFLAGS) -stdlib=libc++

lib_LIBRARIES = libut_dht.a
libut_dht_a_SOURCES = src/DHTMessage.cpp			\
                      src/DhtImpl.cpp				\
                      src/ExternalIPCounter.cpp		\
                      src/blockallocator.cpp		\
                      src/dht.cpp

libut_dht_a_LIBADD = ut_utils/libut_utils.a						\
                     $(top_srcdir)/libtomcrypt/libtomcrypt.a	\
                     $(top_srcdir)/libtommath/libtommath.a

clean-local:
	$(MAKE) -C $(top_srcdir)/libtomcrypt clean
	$(MAKE) -C $(top_srcdir)/libtommath clean

$(top_srcdir)/libtomcrypt/libtomcrypt.a::
	$(MAKE) -C $(top_srcdir)/libtomcrypt CC="$(CC)" CXX="$(CXX)" LD="$(LD)"

$(top_srcdir)/libtommath/libtommath.a::
	$(MAKE) -C $(top_srcdir)/libtommath CC="$(CC)" CXX="$(CXX)" LD="$(LD)"
