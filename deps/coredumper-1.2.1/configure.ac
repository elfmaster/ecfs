## Process this file with autoconf to produce configure.
## In general, the safest way to proceed is to run the following:
##    % aclocal -I `pwd`/../autoconf && autoconf && autoheader && automake

# make sure we're interpreted by some minimal autoconf
AC_PREREQ(2.57)

AC_INIT(coredumper, 1.2.1, opensource@google.com)
# The argument here is just something that should be in the current directory
# (for sanity checking)
AC_CONFIG_SRCDIR(README)
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(src/config.h)

# Checks for programs.
AC_PROG_CC
# This is only needed for linux_syscall_support_unittest, which itself
# only needs c++ for some namespace issues.
AC_PROG_CXX
AC_PROG_INSTALL

AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

# Check whether some low-level functions/files are available
AC_HEADER_STDC

# Here are some examples of how to check for the existence of a fn or file
AC_CHECK_HEADERS([elf.h errno.h fcntl.h linux/unistd.h pthread.h signal.h     \
                  stdlib.h string.h sys/prctl.h sys/ptrace.h sys/resource.h   \
                  sys/socket.h sys/stat.h sys/sysctl.h sys/time.h sys/types.h \
                  sys/uio.h sys/wait.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics
AC_C_CONST

# Checks for library functions
AC_PROG_GCC_TRADITIONAL

# Check if we can force the compiler to generate frame pointers
AC_MSG_CHECKING([whether compiler supports -fno-omit-frame-pointer])
saved_CFLAGS="$CFLAGS"; CFLAGS="-fno-omit-frame-pointer $CFLAGS"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,)],
                  [AC_SUBST(AM_CFLAGS, ["$AM_CFLAGS -fno-omit-frame-pointer"])
                   AC_MSG_RESULT([yes])],
                  [AC_MSG_RESULT([no])])
CFLAGS="$saved_CFLAGS"

# Write generated configuration file
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
