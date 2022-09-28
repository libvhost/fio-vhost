nvme_rpc_path=/var/lib/zbs/aurorad/aurorad-rpc.sock
mkdir -p /var/lib/zbs/aurorad
init() {
    sleep 3
    modprobe null_blk nr_devices=10
    #/root/spdk/scripts/rpc.py -s $nvme_rpc_path construct_malloc_bdev 128 4096 -b Malloc0
    #/root/spdk/scripts/rpc.py -s $nvme_rpc_path bdev_aio_create /dev/sda Malloc0
    #/root/spdk/scripts/rpc.py -s $nvme_rpc_path construct_vhost_blk_controller vhost-blk.0 Malloc0
    for i in `seq 0 9`;do
        /root/spdk/scripts/rpc.py -s $nvme_rpc_path bdev_aio_create /dev/nullb$i Malloc$i
        /root/spdk/scripts/rpc.py -s $nvme_rpc_path vhost_create_blk_controller vhost-blk.$i Malloc$i
    done
}
init &
/root/spdk/build/bin/spdk_tgt -r $nvme_rpc_path -m 0x7 -S /var/lib/zbs/aurorad/ -L vhost -L vhost_blk -L vhost_blk_data -L vhost_ring

# sleep 3
# build/bin/fio examples/vhost-randread-4k.fio
