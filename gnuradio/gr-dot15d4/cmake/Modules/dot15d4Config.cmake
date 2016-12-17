INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_DOT15D4 dot15d4)

FIND_PATH(
    DOT15D4_INCLUDE_DIRS
    NAMES dot15d4/api.h
    HINTS $ENV{DOT15D4_DIR}/include
        ${PC_DOT15D4_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    DOT15D4_LIBRARIES
    NAMES gnuradio-dot15d4
    HINTS $ENV{DOT15D4_DIR}/lib
        ${PC_DOT15D4_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(DOT15D4 DEFAULT_MSG DOT15D4_LIBRARIES DOT15D4_INCLUDE_DIRS)
MARK_AS_ADVANCED(DOT15D4_LIBRARIES DOT15D4_INCLUDE_DIRS)

