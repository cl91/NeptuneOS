cd build
mkdir -p iso/boot/grub
cp images/kernel iso/
cp images/ntos iso/
cat <<EOF > iso/boot/grub/grub.cfg
set timeout=2
menuentry 'seL4-ntos' --class fedora --class gnu-linux --class gnu --class os {
    insmod all_video
    insmod gzio
    insmod part_msdos
    insmod ext2
    echo 'Loading seL4 micro kernel'
    multiboot /kernel
    echo 'Loading ntsvc...'
    module /ntos
}
EOF
grub-mkrescue -o boot.iso iso/
