nvme_rpc_path=/var/lib/zbs/aurorad/aurorad-rpc.sock
mkdir -p /var/lib/zbs/aurorad
cmd_prefix="/root/spdk/scripts/rpc.py -s $nvme_rpc_path"
init() {
    sleep 3
    #/root/spdk/scripts/rpc.py -s $nvme_rpc_path construct_malloc_bdev 128 4096 -b Malloc0
    #/root/spdk/scripts/rpc.py -s $nvme_rpc_path bdev_aio_create /dev/sda Malloc0
    #/root/spdk/scripts/rpc.py -s $nvme_rpc_path construct_vhost_blk_controller vhost-blk.0 Malloc0
    $cmd_prefix bdev_aio_create /dev/nullb0 Malloc0
    $cmd_prefix add_portal_group 1 0.0.0.0:3280
    $cmd_prefix add_initiator_group 2 ANY 192.0.0.0/8
    $cmd_prefix add_initiator_group 3 ANY 127.0.0.0/8
    $cmd_prefix construct_target_node spdk-fl spdk-fl "Malloc0:0" "1:2 1:3" 128
}
init &
/root/spdk/build/bin/spdk_tgt -r $nvme_rpc_path -m 0x7 -S /var/lib/zbs/aurorad/ -L vhost -L vhost_blk -L vhost_blk_data -L vhost_ring

# sleep 3
# build/bin/fio examples/vhost-randread-4k.fio
