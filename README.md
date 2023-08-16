# frida-native-dump
Easy to use [Frida](https://frida.re/) script to dump native libraries (.so files) from running process on Android, 
inspired by [frida_dump](https://github.com/lasting-yang/frida_dump).    

## Features
Block transmission has been introduced to accommodate dump libraries that are larger than the blob size limit of Frida RPC, which is 128 MiB

## Usage
```sh
python dump.py library_name.so
```