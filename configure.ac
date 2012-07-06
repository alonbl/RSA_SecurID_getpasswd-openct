AC_PREREQ(2.59)

AC_INIT([RSA_SecurID_getpasswd-openct], [1.4.5])

AC_CONFIG_AUX_DIR([.])
AM_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([RSA_SecurID_getpasswd.c])
AM_INIT_AUTOMAKE
AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--enable-strict], [enable strict compiler warnings (debugging option) @<:@default=no@:>@])],
	,
	[enable_strict="no"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic], [enable pedantic compiler warnings, will not generate a working executable (debugging option) @<:@default=no@:>@])],
	,
	[enable_pedantic="no"]
)

PKG_PROG_PKG_CONFIG
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_SED
AC_PROG_MAKE_SET

AC_C_CONST
AC_C_INLINE

PKG_CHECK_MODULES(
	[OPENCT],
	[libopenct],
	[AC_DEFINE([ENABLE_OPENCT], [1], [Have OpenCT libraries and header files])],
	[AC_MSG_ERROR([openct requested but not available])]
)

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes"
	CFLAGS="${CFLAGS} -pedantic -ansi"
fi
if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra"
fi

AC_CONFIG_FILES([
	Makefile
])
AC_OUTPUT
