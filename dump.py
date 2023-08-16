import sys
import frida
import os

def add_to_hex(hex_str: str, num: int) -> str:
    """Add an integer to a hex string and return the resulting hex string."""
    int_val = int(hex_str, 16)
    sum_val = int_val + num
    return hex(sum_val)

if __name__ == "__main__":
    device = frida.get_usb_device()
    pid = device.get_frontmost_application().pid
    session = device.attach(pid)
    script = session.create_script(open(os.path.dirname(os.path.abspath(__file__)) + "/script.js", "r").read())
    script.load()

    if len(sys.argv) < 2:
        print('Usage: python dump.py library_name.so')
        exit(0)

    target_name = sys.argv[1]
    module_info = script.exports_sync.module_info(target_name)
    if module_info == -1:
        print("no module found as " + target_name)
        exit(1)

    print(module_info)
    base = module_info["base"]
    size = module_info["size"]
    dump_name = target_name[:-3] + ".dump.so"

    # frida has a limit of buffer size which can be transmitted on RPC
    # this is essential of dumping large libraries
    max_block_size = 100 * 1024 * 1024 # 100 MiB
    i = 0
    with open(dump_name, "wb") as f:
        while size > 0:
            read_size = min(size, max_block_size)
            print('reading part %d %s+%x' % (i, base, read_size))
            i += 1
            f.write(script.exports_sync.dump_memory(base, read_size))
            size -= read_size
            base = add_to_hex(base, read_size)
        f.close()


