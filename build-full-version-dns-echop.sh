#!/bin/zsh

bin="echop"
bin_dir="./bin"

build_failure="$PWD/build_failure.txt"
echo -n > $build_failure

mark(){
    echo $1 >> $build_failure
    echo "[!] make error at $1"
}

build(){
    tag1=$1
    tag2=$2
    target=$3
    if [[ ! -e "${bin_dir}/${bin}-${tag2}" ]]; then
        cur_dir=`pwd`
        ### lwip
        cd ./lwip || exit
        git reset --hard
        git checkout $tag2
        sed -i.bak -e 's/"208.67.222.222"/"8.8.8.8"/g' src/core/dns.c || exit
        sed -i.bak -e 's/resolver1.opendns.com/Google DNS/g' src/core/dns.c || exit
        sed -i.bak -e 's/\(ICMP_DEBUG\s*\)LWIP_DBG_OFF/\1LWIP_DBG_ON/g' src/include/lwip/opt.h || exit
        sed -i.bak -e 's/\(TCP_OUTPUT_DEBUG\s*\)LWIP_DBG_OFF/\1LWIP_DBG_ON/g' src/include/lwip/opt.h || exit
        sed -i.bak -e 's/\(UDP_DEBUG\s*\)LWIP_DBG_OFF/\1LWIP_DBG_ON/g' src/include/lwip/opt.h || exit
        sed -i.bak -e 's/\(DNS_DEBUG\s*\)LWIP_DBG_OFF/\1LWIP_DBG_ON/g' src/include/lwip/opt.h || exit
        sed -i.bak -e 's/\(LWIP_DNS\s*\)0/\1 1/g' src/include/lwip/opt.h || exit
        # patch -l -p1 < "${cur_dir}/patch/enable-dns-debug.patch" || exit
        ### lwip-contrib
        cd ../lwip-contrib
        git reset --hard
        git checkout $tag1
        if [[ $target == *"proj"* ]]; then
            if [[ $tag1 == *"1_4_"* ]]; then
                patch -l -p1 < "${cur_dir}/patch/dns-for-minimal-1-2.patch" || exit
            else
                patch -l -p1 < "${cur_dir}/patch/dns-for-minimal-1.patch" || exit
            fi
        else
            patch -l -p1 < "${cur_dir}/patch/dns-for-minimal-2.patch" || exit
        fi
        ### build directory
        cd $target || exit
        sed -i.bak -e 's/#include "lwip\/udp.h"/#include "lwip\/udp.h"\n#include "lwip\/dns.h"/g' main.c || exit
        sed -i.bak -e 's/$(LWIPDIR)\/core\/init.c/$(LWIPDIR)\/core\/dns.c $(LWIPDIR)\/api\/err.c  $(LWIPDIR)\/core\/init.c/g' Makefile || exit
        sed -i.bak -e 's/\(LWIP_DNS\s*\)0/\1 1/g' lwipopts.h || exit
        sed -i.bak -e 's/\(#define MEMP_NUM_SYS_TIMEOUT\s*\)3/\1 6/g' lwipopts.h || exit
        ### build
        [[ -e Makefile ]] || exit
        echo "CFLAGS += -Wno-error=unused-but-set-variable" >> Makefile
        echo "CFLAGS += -Wno-error=implicit-function-declaration" >> Makefile
        echo "CFLAGS += -Wno-error=discarded-qualifiers" >> Makefile
        echo "CFLAGS += -Wno-error=unused-variable" >> Makefile
        echo "CFLAGS += -Wno-error=incompatible-pointer-types" >> Makefile
        # echo "CFLAGS += -Wno-error=nested-exterrns" >> Makefile
        echo "CFLAGS += -pthread" >> Makefile # (*) Works with gcc 5
        echo "CFLAGS += -Wno-address" >> Makefile # (*) Works with gcc 5
        # echo "CFLAGS += -Wno-error=implicit-fallthrough" >> Makefile # (*) Only works with gcc 7
        make clean
        make -j4 || exit
        cd $cur_dir
        if [[ -e "./lwip-contrib/${target}/${bin}" ]]; then
            mv "./lwip-contrib/${target}/${bin}" "${bin_dir}/${bin}-${tag2}"
        else
            mark $tag2
        fi
    fi
}

target1="./ports/unix/proj/minimal"
target2="./ports/unix/minimal"

build ba11c22 STABLE-1_3_0 $target1
build STABLE-1_3_1 STABLE-1_3_1 $target1
build STABLE-1_3_2 STABLE-1_3_2 $target1
build STABLE-1_4_0 STABLE-1_4_0 $target1
build STABLE-1_4_1 STABLE-1_4_1 $target1
build STABLE-2_0_0_RELEASE STABLE-2_0_0_RELEASE $target2 # compule error
build STABLE-2_0_1 STABLE-2_0_1 $target2 # compule error
build master master $target2

echo "[!] failed versions:"
cat $build_failure

echo "[*] build finished. enjoy"