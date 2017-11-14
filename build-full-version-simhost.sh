#!/bin/zsh

bin="simhost"
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
        cd ./lwip || exit
        git checkout $tag2
        cd ../lwip-contrib
        git reset --hard
        git checkout $tag1
        cd $target || exit
        [[ -e Makefile ]] || exit
        echo "CFLAGS += -Wno-error=unused-but-set-variable" >> Makefile
        echo "CFLAGS += -Wno-error=implicit-function-declaration" >> Makefile
        # echo "CFLAGS += -Wno-error=nested-exterrns" >> Makefile
        echo "CFLAGS += -pthread" >> Makefile # (*) Works with gcc 5
        echo "CFLAGS += -Wno-address" >> Makefile # (*) Works with gcc 5
        # echo "CFLAGS += -Wno-error=implicit-fallthrough" >> Makefile # (*) Only works with gcc 7
        make clean
        make -j4
        cd $cur_dir
        if [[ -e "./lwip-contrib/${target}/${bin}" ]]; then
            mv "./lwip-contrib/${target}/${bin}" "${bin_dir}/${bin}-${tag2}"
        else
            mark $tag2
        fi
    fi
}

target1="./ports/unix/proj/unixsim"
target2="./ports/unix/unixsim"

build ba11c22 STABLE-1_3_0 $target1
build STABLE-1_3_1 STABLE-1_3_1 $target1
build STABLE-1_3_2 STABLE-1_3_2 $target1
build STABLE-1_4_0 STABLE-1_4_0 $target1
build STABLE-1_4_1 STABLE-1_4_1 $target1
build STABLE-2_0_0_RELEASE STABLE-2_0_0_RELEASE $target2 # compule error
build STABLE-2_0_1 STABLE-2_0_1 $target2 # compule error
build master master $target2
