if (C_CODE_BASE64_ENCODE)
    set(COMMON_UTILS_TARGET_FILES
        ${CMAKE_CURRENT_LIST_DIR}/utils.c
        ${CMAKE_CURRENT_LIST_DIR}/utils.h
    )
endif()

target_sources(${PROJECT_NAME}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/applibs_versions.h
    ${CMAKE_CURRENT_LIST_DIR}/azure_iot.c
    ${CMAKE_CURRENT_LIST_DIR}/azure_iot.h
    ${CMAKE_CURRENT_LIST_DIR}/cloud.c
    ${CMAKE_CURRENT_LIST_DIR}/cloud.h
    ${CMAKE_CURRENT_LIST_DIR}/connection.h
    ${CMAKE_CURRENT_LIST_DIR}/eventloop_timer_utilities.c
    ${CMAKE_CURRENT_LIST_DIR}/eventloop_timer_utilities.h
    ${CMAKE_CURRENT_LIST_DIR}/exitcodes.h
    ${CMAKE_CURRENT_LIST_DIR}/user_interface.c
    ${CMAKE_CURRENT_LIST_DIR}/user_interface.h
    ${CMAKE_CURRENT_LIST_DIR}/web_tcp_server.c
    ${CMAKE_CURRENT_LIST_DIR}/web_tcp_server.h
    ${CMAKE_CURRENT_LIST_DIR}/privatenetserv.c
    ${CMAKE_CURRENT_LIST_DIR}/privatenetserv.h
    ${CMAKE_CURRENT_LIST_DIR}/main.c
    ${CMAKE_CURRENT_LIST_DIR}/options_args_parser.c
    ${CMAKE_CURRENT_LIST_DIR}/options.h
    ${CMAKE_CURRENT_LIST_DIR}/parson.c
    ${CMAKE_CURRENT_LIST_DIR}/parson.h
    ${CMAKE_CURRENT_LIST_DIR}/mt3620_avnet_dev.h
    ${CMAKE_CURRENT_LIST_DIR}/mt3620_rdb.h
    ${CMAKE_CURRENT_LIST_DIR}/resource.h
    ${COMMON_UTILS_TARGET_FILES}
)
