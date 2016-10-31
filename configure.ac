#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([libnss-dummy], [0.1.0], [pandax381@gmail.com])
AM_INIT_AUTOMAKE(foreign)
AC_CONFIG_SRCDIR([libnss-dummy.c])
AC_CONFIG_HEADERS([config.h])
AC_DISABLE_STATIC
LT_INIT

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_CHECK_FUNCS([gethostname memset])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
