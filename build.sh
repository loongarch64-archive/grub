# 编译
# 安装unifont字体文件，以便让grub在编译和安装时生成pf2字体。
#sudo apt install ttf-unifont ttf-dejavu libfreetype6-dev efibootmgr

# 在线下载 po 文件
if [ $# -eq 1 ];then
  ./linguas.sh
  ./bootstrap
fi

mkdir -p _build
cd _build
if [ -f /usr/share/fonts/TTF/DejaVuSans.ttf ]; then
  cp /usr/share/fonts/TTF/DejaVuSans.ttf .
fi

../configure \
    --disable-dependency-tracking \
    --prefix=/usr \
    --exec-prefix=/usr \
    --bindir=/usr/bin \
    --sbindir=/usr/sbin \
    --sysconfdir=/etc \
    --datadir=/usr/share \
    --includedir=/usr/include \
    --libdir=/usr/lib \
    --libexecdir=/usr/lib \
    --localstatedir=/var \
    --sharedstatedir=/var/lib \
    --mandir=/usr/share/man \
    --infodir=/usr/share/info \
    --with-platform=efi \
    --enable-grub-mount \
    --enable-mm-debug \
    --enable-boot-time \
    --disable-werror 2>&1 | tee build.log


make -j8 2>&1 | tee -a build.log
# 编译翻译文件
make -C po update-gmo 2>&1 | tee -a build.log

#sudo make install

# 安装
# grub-mkinstall /dev/sda

# EFI 文件自动生成在 /boot/efi/EFI/arch/grubloongarch64.efi, /boot/grub下面会自动安装好fonts、locale  mips64el-efi  themes等等。

# 配置
# 修改 /etc/default/grub 配置文件，让grub正常显示中文：
# GRUB_TERMINAL_OUTPUT="gfxterm"

# 运行 sudo grub-mkconfig -o /boot/grub/grub.cfg
# 重启系统，应该一切正常。
