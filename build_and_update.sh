c7 () {
	docker run --ulimit nofile=10240:10240 -it --rm --privileged -w `pwd` -v /dev/hugepages:/dev/hugepages -v /dev/shm:/dev/shm -v /root/:/root/ -v /var/log/zbs:/var/log/zbs -v /tmp:/tmp -v /var/crash:/var/crash $1 bash -c ". /opt/rh/devtoolset-7/enable;export PATH=/usr/lib64/ccache/:\$PATH;which gcc; gcc -v;$2"
}

/bin/rm -rf rpm
for arch in oe1-aarch64 oe1-x86_64 el7-x86_64;do
#for arch in el7-x86_64 ;do
    echo "===================== $arch ========================="
    image=registry.smtx.io/zbs/zbs-buildtime:$arch
    /bin/rm -rf build 2>/dev/null
    c7 $image "TYPE=rel ./build.sh; strip build/bin/fio-vhost"
    [ $? -eq 0 ] || exit 1
    #mkdir -p rpm/$arch
    #cp -r /root/fio-vhost/build/fio-vhost-3.27.417-Linux.rpm rpm/$arch
    #cp build/bin/fio-vhost rpm/$arch
    #archdir=`echo $arch | awk -F- '{printf "%s/%s", $2, $1}'`
    [ $arch = "el7-x86_64" ] && archdir="x86_64/el7"
    [ $arch = "oe1-x86_64" ] && archdir="x86_64/oe"
    [ $arch = "oe1-aarch64" ] && archdir="aarch64/oe"
    cp build/bin/fio-vhost /root/kvm-bench/${archdir}
done
