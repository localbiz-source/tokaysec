parted -s /dev/sdb mklabel gpt
parted -s /dev/sdb mkpart KEKPartition 1MiB 20MiB # kek1, kek2, kek3, ...
cryptsetup luksFormat /dev/sdb1
cryptsetup open /dev/sdb1 kek_partition