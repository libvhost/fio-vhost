export ASAN_OPTIONS=disable_coredump=0:unmap_shadow_on_exit=1:fast_unwind_on_malloc=0;
type=${TYPE:-asan}
[ $type = "asan" ] && type=ASan
[ $type = "ubsan" ] && type=UBSan
[ $type = "reldeb" ] && type=RelWithDebInfo
[ $type = "rel" ] && type=Release
[ $type = "debug" ] && type=Debug
cmake -B build -GNinja -DCMAKE_BUILD_TYPE=$type -DCMAKE_INSTALL_PREFIX=build
# ninja -C build -v
ninja -C build install -v
cd build; cpack3
cd -
