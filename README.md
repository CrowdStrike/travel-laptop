# A Reasonably Secure Travel Laptop Setup #

This repository contains auxiliary scripts and configurations around building a reasonably secure travel laptop using [coreboot](https://www.coreboot.org/) with a [GRUB2](http://www.gnu.org/software/grub/) payload.
The scripts and configurations have been tested with an [ArchLinux](https://www.archlinux.org/) setup but should be adaptable to other distributions easily.

A reasonably secure travel laptop following the approach laid out here will boot only a signed kernel and initrd and assure user-space integrity with a [dm-verity](https://lwn.net/Articles/459420/) protected root filesystem. If you require confidentiality, it is additionally recommended encrypted the entire filesystem or use a separate, encrypted `/home` partition.

Building coreboot and GRUB2 for your target laptop and flashing the appropriate image is out of the scope of this repository's contents and documentation. You can find more information on the [coreboot Wiki](https://coreboot.org/Welcome_to_coreboot).

## Involved Components ##

The resources contained in this repository are used in the boot chain as follows:
- A GRUB2 configuration file is embedded into a GRUB2 `memdisk` on the SPI Flash itself. It serves as the root of the chain of trust and loads the signing key from the GRUB2 `memdisk`, transitions the GRUB2 `root` to the boot device / partition and hands over to a *signed* GRUB2 configuration there.
- The GRUB2 configuration on the boot device/partition loads the Linux kernel and initrd or whatever other payload you want to load. It will provide the [dm-verity](https://lwn.net/Articles/459420/) root hash to the initrd, which in turn assigns it to the `dm-verity` device. Because this configuration is signed, the `dm-verity` root hash is signed and transitively the root filesystem is authenticated.
- Because a `dm-verity` root filesystem must be read-only and is not supported by most distributions' generic initrd generation scripts, a special set of scripts to support a `tmpfs` backed [overlayfs](https://www.kernel.org/doc/Documentation/filesystems/overlayfs.txt) mounted from the initrd and intializing the `dm-verity` device with the right root hash is required. This set of scripts will hook into the `mkinitcpio` script on ArchLinux, it must be adapted for other distributions to generate an initrd compatible with this setup.


### GRUB2 Configuration in SPI Flash ###

The initial GRUB2 configuration to be loaded from the SPI flash is used to kick off a more accessible but *signed* configuration from the boot device/partition.
An examplary script that loads a signing key from the GRUB2 `memdisk` is provided in this repository under [`grub-cfg/memdisk-grub.cfg`](grub-cfg/memdisk-grub.cfg).

Generally, it is recommended to create a directory representing the additional memory disk contents of GRUB2 and invoking `grub-mkstandalone` from there:
- Create an empty directory representing your `memdisk` somewhere and change to that directory.
- Copy [`grub-cfg/memdisk-grub.cfg`](grub-cfg/memdisk-grub.cfg) to `boot/grub/grub.cfg` relative to the `memdisk` base directory, adjust it to your needs.
- Export your signing public key to `boot/${keyid}.gpg` and fix the path in the `grub.cfg`
- Invoke `grub-mkstandalone` from the `memdisk` base directory as follows to create a coreboot payload image with the appropriate `memdisk` contents:
```
grub-mkstandalone -O i386-coreboot -o ../grub_coreboot_payload.elf --compress=none --themes='' --locales='' boot/grub/grub.cfg boot/${keyid}.gpg
```

You can now reference `../grub_coreboot_payload.elf` as ELF payload in the coreboot `Kconfig` to be directly built in or alternatively add it manually with `cbfstool`.

### GRUB2 Configuration on boot device/partition ###

When using a GRUB2 configuration in SPI flash derived from [`grub-cfg/memdisk-grub.cfg`](grub-cfg/memdisk-grub.cfg), signature verification of the kernel and initrd will be mandatory already.
Your configuration merely has to load the kernel with the correct command line and reference the right initrd.

The initrd scripts in this repository understand the following command line options:
- `overlay_verity_dev`: device name for the device containing the dm-verity hash tree, created with `veritysetup`. If you just want to test a read-only root filesystem with a `tmpfs` backed `overlayfs`, set this to anything and do not specify the `overlay_verity_root` option on the command line.
- `overlay_verity_root`: the root hash of the dm-verity hash tree on the device provided in `overlay_verity_dev`. This will activate actual root filesystem block integrity checking.
- `root`: as usual, this is the root filesystem backing device, which will then be read-only and integrity protected.

An exemplary configuration file can be found in [`grub-cfg/bootdrive-grub.cfg`](grub-cfg/bootdrive-grub.cfg).


### mkinitcpio Hook ###

To generate an initrd/initramfs/initcpio that initializes dm-verity and creates a `tmpfs` backed `overlayfs` around it, a hook for `mkinitcpio` is required. This hook is provided within [`etc-initcpio/`](etc-initcpio/), simply copy the directory contents to your `/etc/initcpio` directory and add the `overlay_verity` hook to your `/etc/mkinitcpio.conf` in the  `HOOKS` array after the `filesystems` hook. If you have a `fsck` hook, be sure to remove it as it will tamper with the root filesystem's on-disk header and cause verification failures.


## Step-by-step Setup ##

1. First, install [ArchLinux](https://www.archlinux.org/) (or one of its derivatives, such as [BlackArch](http://blackarch.org/)) on your target devices internal drive, ensure to have a separate `/boot` partition. Make sure that you have all your tools and your root filesystem is *ready to be frozen*. At this point, you should also have set up any encrypted `/home` partitions and similar.
2. Make sure you have installed [the mkinitcpio hook](etc-initcpio/) from this repository and your initrd/initramfs/initcpio has been updated with `mkinitcpio`. Double check with `lsinitcpio` that a module for your root filesystem (for example `ext4.ko`) is present.
3. Now it is time to flash the coreboot and GRUB2 image onto your device's SPI flash. Make sure you can disable signature verification for the setup step by using the GRUB2 command line and entering `set check_signature=''`; this will require posessing the PBKDF2 superuser password, see [`grub-cfg/memdisk-grub.cfg`](grub-cfg/memdisk-grub.cfg).
4. Load your operating system with a read-only root and a fake `overlayfs` by providing a command line containg `overlay_verity_dev=y` but no `overlay_verity_root` option.
5. You can now [populate the dm-verity hash tree on the appropriate device using `veritysetup format`](https://gitlab.com/cryptsetup/cryptsetup/wikis/DMVerity). Be sure to copy the root hash!
6. Update your [boot device `grub.cfg`](grub-cfg/bootdrive-grub.cfg) by providing the real `overlay_verity_dev` you just populated and setting the root hash with `overlay_verity_root`.
7. Sign your boot device `grub.cfg`, the kernel and the initrd/initramfs/initcpio using `gpg --detach-sign` (optionally specify the right signing key with `--local-user`).
