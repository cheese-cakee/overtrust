#!/bin/bash
set -e
cd /mnt/c/Users/lenovo/overtrust
sudo apt-get update -qq 2>&1 | tail -1
sudo apt-get install -y -qq cmake g++ 2>&1 | tail -1
rm -rf build_linux
mkdir build_linux
cd build_linux
cmake .. -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -5
cmake --build . -j`nproc` 2>&1 | tail -5
cp overtrust /mnt/c/Users/lenovo/overtrust/overtrust-linux
echo "Linux binary: overtrust-linux"
chmod +x /mnt/c/Users/lenovo/overtrust/overtrust-linux
