file(GLOB LIBISCSI_HEADERS ${LIBISCSI_SOURCE_DIR}/include/*.h)
file(COPY ${LIBISCSI_HEADERS} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/libiscsi/include/iscsi)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/libiscsi/include)

add_library(iscsi_fio_plugin STATIC ${FIO_SOURCE_DIR}/engines/libiscsi.c)
add_dependencies(iscsi_fio_plugin fio-ext libiscsi_static)

add_executable(fio fio.c nvme.c vhost.c pmem.c ioat.c)
add_dependencies(fio fio-ext)
set(FIO_LIBRARY -Wl,--whole-archive iscsi_fio_plugin libiscsi_static fio_static -Wl,--no-whole-archive gcrypt)
target_link_libraries(fio PRIVATE ${FIO_LIBRARY} tcmalloc numa z m pthread dl aio ibverbs rdmacm curl ssl crypto pmem vhost vfio)

install(TARGETS fio DESTINATION bin COMPONENT fio)
install(FILES ${CMAKE_SOURCE_DIR}/fio/tools/genfio
    PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE GROUP_EXECUTE WORLD_EXECUTE GROUP_READ WORLD_READ
    DESTINATION bin COMPONENT fio)
