INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_WMBUS wmbus)

FIND_PATH(
    WMBUS_INCLUDE_DIRS
    NAMES wmbus/api.h
    HINTS $ENV{WMBUS_DIR}/include
        ${PC_WMBUS_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    WMBUS_LIBRARIES
    NAMES gnuradio-wmbus
    HINTS $ENV{WMBUS_DIR}/lib
        ${PC_WMBUS_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(WMBUS DEFAULT_MSG WMBUS_LIBRARIES WMBUS_INCLUDE_DIRS)
MARK_AS_ADVANCED(WMBUS_LIBRARIES WMBUS_INCLUDE_DIRS)

