IF (WIN32)
	find_library(WSOCK32_LIBRARY wsock32)
	find_library(WS2_32_LIBRARY ws2_32)
	set(visca_SOURCES
		libvisca.c
		libvisca_win32.c
		libvisca_tcp.c
		libvisca_udp.c
	)

	if (WITH_VISCA_SERIAL)
		set(visca_SOURCES ${visca_SOURCES} libvisca_serial_win32.c)
	endif()

	add_library(visca ${visca_SOURCES})

	if(BUILD_SHARED_LIBS)
		set_target_properties(visca PROPERTIES COMPILE_DEFINITIONS "VISCA_API=__declspec(dllexport)")
	else()
		set_target_properties(visca PROPERTIES COMPILE_DEFINITIONS "VISCA_API=")
	endif()
	target_link_libraries(visca wsock32 ws2_32)
ELSE()
	set(visca_SOURCES
		libvisca.c
		libvisca_posix.c
		libvisca_tcp.c
		libvisca_udp.c
	)
	if (WITH_VISCA_SERIAL)
		set(visca_SOURCES ${visca_SOURCES} libvisca_serial_posix.c)
	endif()
	add_library(visca ${visca_SOURCES})

SET_TARGET_PROPERTIES(visca PROPERTIES SOVERSION 0.2.0)
ENDIF()

INSTALL(TARGETS visca DESTINATION lib${LIB_SUFFIX})
INSTALL(FILES libvisca.h DESTINATION include/libvisca)
