# Configure script for Digital Bazaar Bitmunk product line
# Usage: Run ./configure once 
# Author: Manu Sporny

AC_PREREQ([2.60])
AC_INIT([forge],[0.1.0],[support@digitalbazaar.com])
AC_CONFIG_AUX_DIR(setup)

# Setup standard build environment variables
# FIXME: allow changing via configure option
FORGE_DIR=`(cd ${srcdir} && pwd)`
AC_SUBST(FORGE_DIR)
DATE_YMD=`date +%Y%m%d`
PACKAGE_DATE_VERSION=${PACKAGE_VERSION}-${DATE_YMD}
AC_SUBST(DATE_RFC_2822)
AC_SUBST(PACKAGE_DATE_VERSION)

dnl ----------------- docs -----------------

AC_ARG_ENABLE([docs],
   AS_HELP_STRING([--enable-docs], [build documentation [[no]]]),
   [ 
      case "${enableval}" in
         yes) BUILD_DOCS=yes ;;
         no) BUILD_DOCS=no ;;
         *) AC_MSG_ERROR(bad value ${enableval} for --enable-docs) ;;
      esac
   ], [BUILD_DOCS=no]) dnl Default value

AC_SUBST(BUILD_DOCS)

dnl ----------------- tests -----------------

AC_ARG_ENABLE([tests],
   AC_HELP_STRING([--disable-tests], [disable building test apps [[no]]]),
   [
   case "${enableval}" in
      yes) BUILD_TESTS=yes ;;
      no)  BUILD_TESTS=no ;;
      *)   AC_MSG_ERROR(bad value ${enableval} for --disable-tests) ;;
   esac
   ], [BUILD_TESTS=no]) dnl Default value

AC_SUBST(BUILD_TESTS)

dnl ----------------- build flash -----------------

AC_ARG_ENABLE([flash],
   AC_HELP_STRING([--enable-flash], [enable building flash [[yes]]]),
   [
   case "${enableval}" in
      yes) BUILD_FLASH=yes ;;
      no)  BUILD_FLASH=no ;;
      *)   AC_MSG_ERROR(bad value ${enableval} for --disable-flash) ;;
   esac
   ], [BUILD_FLASH=yes]) dnl Default value

AC_SUBST(BUILD_FLASH)

dnl ----------------- mxmlc -----------------

AC_ARG_WITH([mxmlc],
   AC_HELP_STRING([--with-mxmlc=PATH],
      [use PATH for mxmlc]),
   [
      case "${withval}" in
         yes|no) AC_MSG_ERROR(bad value ${withval} for --with-mxmlc) ;;
         *)      MXMLC="${withval}" ;;
      esac
      if test "x$MXMLC" = x -o ! -x "$MXMLC"; then
         AC_MSG_ERROR([mxmlc not found at "$MXMLC"])
      fi
   ])

if test "$BUILD_FLASH" = "yes" ; then
   dnl Need to try to find mxmlc
   if test "x$MXMLC" = x; then
      AC_CHECK_PROGS(MXMLC, mxmlc /usr/lib/flex3/bin/mxmlc,, $PATH /)
   fi
   dnl Check that mxmlc was found
   if test "x$MXMLC" = x; then
      AC_MSG_ERROR([mxmlc not found, try --with-mxmlc])
   fi
   AC_SUBST(MXMLC)
fi

dnl ----------------- mxmlc debug -----------------

AC_ARG_ENABLE([mxmlc-debug],
   AC_HELP_STRING([--enable-mxmlc-debug], [enable mxmlc debug mode [[false]]]),
   [
   case "${enableval}" in
      yes) MXMLC_DEBUG_MODE=true ;;
      no)  MXMLC_DEBUG_MODE=false ;;
      *)   AC_MSG_ERROR(bad value ${enableval} for --enable-mxmlc-debug) ;;
   esac
   ], [MXMLC_DEBUG_MODE=false]) dnl Default value

AC_SUBST(MXMLC_DEBUG_MODE)

dnl ----------------- end of options -----------------

echo -e "\n--------- Configuring Build Environment -----------"

PKG_PROG_PKG_CONFIG

# Checking for standard build tools
AC_PROG_INSTALL()
AS_PATH_PYTHON([2.5])

dnl ----------------------------------

# Generating files
AC_CONFIG_FILES([
   .gitignore
   Makefile
])

# add newlines to internal output file list
CONFIGURE_GENERATED_FILES="`echo $ac_config_files | tr ' ' '\n'`"
AC_SUBST(CONFIGURE_GENERATED_FILES)

AC_OUTPUT

# Dump the build configuration

echo -e "\n--------- Forge Build Environment -----------"
echo "Forge Version     : $PACKAGE_NAME $PACKAGE_DATE_VERSION"

if test "$BUILD_FLASH" = "yes" ; then
   echo "Python:           : $PYTHON (version $PYTHON_VERSION)"
   echo "Adobe Flash       : enabled"
   echo "MXMLC             : $MXMLC"
   echo "MXMLC Debug flags : $MXMLC_DEBUG_MODE"
else
   echo "Adobe Flash       : disabled (use --enable-flash to enable)"
fi

if test "x$BUILD_DOCS" = "xyes"; then
   echo "Documentation     : enabled"
else
   echo "Documentation     : disabled (use --enable-docs to enable)"
fi

if test "x$BUILD_TESTS" = "xyes"; then
   echo "Tests             : enabled"
else
   echo "Tests             : disabled (use --enable-tests to enable)"
fi

