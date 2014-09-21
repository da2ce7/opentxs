#!/usr/bin/env bash

# Install cppcheck on Ubuntu from source since we need a recent version.
# Will not be needed once travis is updated to Ubuntu 14.04.
install_cppcheck()
{
    git clone https://github.com/danmar/cppcheck.git
    cd cppcheck
    git checkout $(cat ../scripts/travis/cppcheck_version)
    make CFGDIR=/usr/share/cppcheck/cfg HAVE_RULES=no -j2
    sudo make CFGDIR=/usr/share/cppcheck/cfg install
    cd ..
    rm -rf ./cppcheck/
}

if [ $# -ne 1 ]; then
    echo "Error: expected OS type argument." >&2
    exit 1
fi

os=$1

case "$os" in
    osx)
        brew update
        brew unlink cmake
        brew install protobuf-c protobuf boost cppcheck cmake zeromq pstree
        ;;
    linux|"" )
        wget -O - http://llvm.org/apt/llvm-snapshot.gpg.key | sudo apt-key add -
        sudo add-apt-repository -y \
            "deb http://llvm.org/apt/precise/ llvm-toolchain-precise-3.5 main"
        sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
        sudo add-apt-repository -y ppa:chris-lea/zeromq
        sudo apt-get -qq update
        sudo apt-get -qq install g++-4.8
        sudo apt-get install libprotobuf-dev protobuf-compiler \
            libboost-all-dev doxygen libzmq3-dev clang-format-3.5
        sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 50
        sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-4.8 50
        install_cppcheck
        ;;
    *)
        echo "Error: unknown OS '$os'" >&2
        exit 1
        ;;
esac

git clone https://github.com/zeromq/cppzmq.git
sudo cp cppzmq/zmq.hpp /usr/local/include/
