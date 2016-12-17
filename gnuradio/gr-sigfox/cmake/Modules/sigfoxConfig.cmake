INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_SIGFOX sigfox)

FIND_PATH(
    SIGFOX_INCLUDE_DIRS
    NAMES sigfox/api.h
    HINTS $ENV{SIGFOX_DIR}/include
        ${PC_SIGFOX_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    SIGFOX_LIBRARIES
    NAMES gnuradio-sigfox
    HINTS $ENV{SIGFOX_DIR}/lib
        ${PC_SIGFOX_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(SIGFOX DEFAULT_MSG SIGFOX_LIBRARIES SIGFOX_INCLUDE_DIRS)
MARK_AS_ADVANCED(SIGFOX_LIBRARIES SIGFOX_INCLUDE_DIRS)

