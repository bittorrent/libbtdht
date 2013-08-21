AC_PREREQ([2.69])
AC_INIT([uTorrent DHT], [0.1],
        [utorrent-bugs@bittorrent.com],
        [ut_dht])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign nostdinc silent-rules subdir-objects tar-ustar -Wall])
AM_SILENT_RULES([yes])
AM_PROG_AR

if test -z "$CFLAGS"; then
   CFLAGS=''
fi

if test -z "$CXXFLAGS"; then
   CXXFLAGS=''
fi

AC_PROG_CC
AC_PROG_CXX
AC_PROG_RANLIB

AC_ARG_ENABLE(debug,
              AS_HELP_STRING([--enable-debug], [enable debugging, default: no]),
              [case "${enableval}" in
                 yes) debug=true ;;
                 no) debug=false ;;
                 *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
               esac],
               [debug=false])

AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

AC_CONFIG_SUBDIRS([ut_utils])

AC_OUTPUT(Makefile)
