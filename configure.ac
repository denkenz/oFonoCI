AC_PREREQ([2.69])
AC_INIT([ofono], [2.18])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR(build-aux)

AC_REQUIRE_AUX_FILE([tap-driver.sh])

AM_INIT_AUTOMAKE([foreign subdir-objects color-tests silent-rules
					tar-pax no-dist-gzip dist-xz])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

PKG_PROG_PKG_CONFIG

COMPILER_FLAGS

AC_LANG([C])

AC_C_RESTRICT

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CC_PIE
AC_PROG_CC_ASAN
AC_PROG_CC_LSAN
AC_PROG_CC_UBSAN
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_PROG_AWK

m4_define([_LT_AC_TAGCONFIG], [])
m4_ifdef([AC_LIBTOOL_TAGS], [AC_LIBTOOL_TAGS([])])

AC_DISABLE_STATIC
LT_INIT

AC_ARG_ENABLE(optimization, AS_HELP_STRING([--disable-optimization],
			[disable code optimization through compiler]), [
	if (test "${enableval}" = "no"); then
		CFLAGS="$CFLAGS -O0"
	fi
])

if (test "${enable_optimization}" != "no"); then
	CFLAGS="$CFLAGS -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2"
fi

AC_ARG_ENABLE(debug, AS_HELP_STRING([--enable-debug],
			[enable compiling with debugging information]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g"
	fi
])

AC_ARG_ENABLE(pie, AS_HELP_STRING([--enable-pie],
			[enable position independent executables flag]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_pie}" = "yes"); then
		CFLAGS="$CFLAGS -fPIE"
		LDFLAGS="$LDFLAGS -pie"
	fi
])

save_LIBS=$LIBS
AC_CHECK_LIB(asan, _init)
LIBS=$save_LIBS

AC_ARG_ENABLE(asan, AS_HELP_STRING([--enable-asan],
			[enable linking with address sanitizer]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_lib_asan__init}" = "yes" &&
				test "${ac_cv_prog_cc_asan}" = "yes"); then
		CFLAGS="$CFLAGS -fsanitize=address";
		LDFLAGS="$LDFLAGS -fsanitize=address"
	fi
])

save_LIBS=$LIBS
AC_CHECK_LIB(lsan, _init)
LIBS=$save_LIBS

AC_ARG_ENABLE(lsan, AS_HELP_STRING([--enable-lsan],
			[enable linking with leak sanitizer]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_lib_lsan__init}" = "yes" &&
				test "${ac_cv_prog_cc_lsan}" = "yes"); then
		CFLAGS="$CFLAGS -fsanitize=leak";
		LDFLAGS="$LDFLAGS -fsanitize=leak"
	fi
])

save_LIBS=$LIBS
AC_CHECK_LIB(ubsan, _init)
LIBS=$save_LIBS

AC_ARG_ENABLE(ubsan, AS_HELP_STRING([--enable-ubsan],
			[enable linking with undefined behavior sanitizer]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_lib_ubsan__init}" = "yes" &&
				test "${ac_cv_prog_cc_ubsan}" = "yes"); then
		CFLAGS="$CFLAGS -fsanitize=undefined";
		LDFLAGS="$LDFLAGS -fsanitize=undefined"
	fi
])

AC_CHECK_FUNCS(explicit_bzero)
AC_CHECK_FUNCS(rawmemchr)

# In maintainer mode: try to build with application backtrace and disable PIE.
if (test "${USE_MAINTAINER_MODE}" = yes); then
	AC_SEARCH_LIBS([backtrace], [execinfo],
		[
			AC_DEFINE([HAVE_BACKTRACE], [1],
				[Define to 1 if you have backtrace(3).])
			CFLAGS="$CFLAGS -fno-PIE"
			LDFLAGS="$LDFLAGS -no-pie"
		])
fi

AC_CHECK_FUNC(signalfd, dummy=yes,
			AC_MSG_ERROR(signalfd support is required))

AC_CHECK_LIB(dl, dlopen, dummy=yes,
			AC_MSG_ERROR(dynamic linking loader is required))

PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.68, [
	AC_DEFINE_UNQUOTED(HAVE_G_MEMDUP2, 1,
			[Define to 1 if you have the `g_memdup2' function.])
], [
	PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.32, dummy=yes,
				AC_MSG_ERROR(GLib >= 2.32 is required))
])
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.6, dummy=yes,
				AC_MSG_ERROR(D-Bus >= 1.6 is required))
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

AC_ARG_WITH(dbusconfdir, AS_HELP_STRING([--with-dbusconfdir=PATH],
	[path to D-Bus config directory]), [path_dbusconf=${withval}],
		[path_dbusconf="`$PKG_CONFIG --variable=sysconfdir dbus-1`"])
if (test -z "${path_dbusconf}"); then
	DBUS_CONFDIR="${sysconfdir}/dbus-1/system.d"
else
	DBUS_CONFDIR="${path_dbusconf}/dbus-1/system.d"
fi
AC_SUBST(DBUS_CONFDIR)

AC_ARG_WITH(dbusdatadir, AS_HELP_STRING([--with-dbusdatadir=PATH],
	[path to D-Bus data directory]), [path_dbusdata=${withval}],
		[path_dbusdata="`$PKG_CONFIG --variable=datadir dbus-1`"])
if (test -z "${path_dbusdata}"); then
	DBUS_DATADIR="${datadir}/dbus-1/system-services"
else
	DBUS_DATADIR="${path_dbusdata}/dbus-1/system-services"
fi
AC_SUBST(DBUS_DATADIR)

AC_ARG_WITH([systemdunitdir], AS_HELP_STRING([--with-systemdunitdir=DIR],
	[path to systemd service directory]), [path_systemdunit=${withval}],
		[path_systemdunit="`$PKG_CONFIG --variable=systemdsystemunitdir systemd`"])
if (test -n "${path_systemdunit}"); then
	SYSTEMD_UNITDIR="${path_systemdunit}"
	AC_SUBST(SYSTEMD_UNITDIR)
fi
AM_CONDITIONAL(SYSTEMD, test -n "${path_systemdunit}")

AC_ARG_ENABLE(test, AS_HELP_STRING([--enable-test],
		[enable test/example scripts]), [enable_test=${enableval}])
AM_CONDITIONAL(TEST, test "${enable_test}" = "yes")

AC_ARG_ENABLE(tools, AS_HELP_STRING([--enable-tools],
		[enable testing tools]), [enable_tools=${enableval}])
AM_CONDITIONAL(TOOLS, test "${enable_tools}" = "yes")

AC_ARG_ENABLE(dundee, AS_HELP_STRING([--enable-dundee],
		[enable dialup deamon support]), [enable_dundee=${enableval}])
AM_CONDITIONAL(DUNDEE, test "${enable_dundee}" = "yes")

AC_ARG_ENABLE(udev, AS_HELP_STRING([--disable-udev],
			[disable udev modem detection support]),
						[enable_udev=${enableval}])
if (test "${enable_udev}" != "no"); then
	PKG_CHECK_MODULES(UDEV, libudev >= 143, [enable_udev="yes"],
				AC_MSG_ERROR(libudev >= 143 is required))
	UDEV_DATADIR="`$PKG_CONFIG --variable=udevdir udev`"
	if (test -z "${UDEV_DATADIR}"); then
		UDEV_DATADIR="${sysconfdir}/udev/rules.d"
	else
		UDEV_DATADIR="${UDEV_DATADIR}/rules.d"
	fi
	AC_SUBST(UDEV_DATADIR)
fi
AC_SUBST(UDEV_CFLAGS)
AC_SUBST(UDEV_LIBS)
AM_CONDITIONAL(UDEV, test "${enable_udev}" = "yes")

AC_ARG_ENABLE(atmodem, AS_HELP_STRING([--disable-atmodem],
				[disable ETSI AT modem support]),
					[enable_atmodem=${enableval}])
AM_CONDITIONAL(ATMODEM, test "${enable_atmodem}" != "no")

AC_ARG_ENABLE(phonesim, AS_HELP_STRING([--disable-phonesim],
				[disable Phone simulator support]),
					[enable_phonesim=${enableval}])
AM_CONDITIONAL(PHONESIM, test "${enable_phonesim}" != "no" &&
					test "${enable_atmodem}" != "no")

AC_ARG_ENABLE(isimodem, AS_HELP_STRING([--disable-isimodem],
				[disable PhoNet/ISI modem support]),
					[enable_isimodem=${enableval}])
AM_CONDITIONAL(ISIMODEM, test "${enable_isimodem}" != "no")

AC_ARG_ENABLE(rilmodem, AS_HELP_STRING([--disable-rilmodem],
				[disable RIL modem support]),
					[enable_rilmodem=${enableval}])
AM_CONDITIONAL(RILMODEM, test "${enable_rilmodem}" != "no")

AC_ARG_ENABLE(qmimodem, AS_HELP_STRING([--disable-qmimodem],
				[disable Qualcomm QMI modem support]),
					[enable_qmimodem=${enableval}])
AM_CONDITIONAL(QMIMODEM, test "${enable_qmimodem}" != "no")

AC_ARG_ENABLE(mbimmodem, AS_HELP_STRING([--disable-mbimmodem],
				[disable MBIM modem support]),
					[enable_mbimmodem=${enableval}])
AM_CONDITIONAL(MBIMMODEM, test "${enable_mbimmodem}" != "no")

AC_ARG_ENABLE(bluetooth, AS_HELP_STRING([--disable-bluetooth],
				[disable BlueZ 5 plugins support]),
					[enable_bluetooth=${enableval}])

AM_CONDITIONAL(BLUETOOTH, test "${enable_bluetooth}" != "no")

AC_ARG_ENABLE(upower, AS_HELP_STRING([--disable-upower],
			[disable UPower plugin]),
					[enable_upower=${enableval}])
AM_CONDITIONAL(UPOWER, test "${enable_power}" != "no")

AC_ARG_ENABLE([external_ell], AS_HELP_STRING([--enable-external-ell],
				[enable external Embedded Linux library]),
					[enable_external_ell=${enableval}])
if (test "${enable_external_ell}" = "yes"); then
	PKG_CHECK_MODULES(ELL, ell >= 0.79, dummy=yes,
		AC_MSG_ERROR(Embedded Linux library >= 0.72 is required))
	AC_SUBST(ELL_CFLAGS)
	AC_SUBST(ELL_LIBS)
fi
AM_CONDITIONAL(EXTERNAL_ELL, test "${enable_external_ell}" = "yes")

AC_ARG_ENABLE(datafiles, AS_HELP_STRING([--disable-datafiles],
			[do not install configuration and data files]),
					[enable_datafiles=${enableval}])
AM_CONDITIONAL(DATAFILES, test "${enable_datafiles}" != "no")

if (test "${prefix}" = "NONE"); then
	dnl no prefix and no localstatedir, so default to /var
	if (test "$localstatedir" = '${prefix}/var'); then
		AC_SUBST([localstatedir], ['/var'])
	fi

	prefix="${ac_default_prefix}"
fi

if (test "$localstatedir" = '${prefix}/var'); then
	storagedir="${prefix}/var/lib/ofono"
else
	storagedir="${localstatedir}/lib/ofono"
fi
AC_DEFINE_UNQUOTED(STORAGEDIR, "${storagedir}",
			[Directory for the storage files])

if (test "$sysconfdir" = '${prefix}/etc'); then
	configdir="${prefix}/etc/ofono"
else
	configdir="${sysconfdir}/ofono"
fi
AC_DEFINE_UNQUOTED(CONFIGDIR, "${configdir}",
			[Directory for the configuration files])

AC_CONFIG_FILES(Makefile include/version.h src/ofono.service ofono.pc \
		dundee/dundee.service)

AC_DEFINE([_auto_], [__L_AUTODESTRUCT], [autodestruct syntax])
AC_OUTPUT
