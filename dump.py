import sys
import frida
import os

ZERO_BLOCK_SIZE = 1024 * 1024


def write_zeros(output, size: int) -> None:
    block = b"\0" * min(size, ZERO_BLOCK_SIZE)
    while size > 0:
        write_size = min(size, len(block))
        output.write(block[:write_size])
        size -= write_size


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
    base = int(module_info["base"], 16)
    size = module_info["size"]
    dump_name = target_name[:-3] + ".dump.so"

    # frida has a limit of buffer size which can be transmitted on RPC
    # this is essential of dumping large libraries
    max_block_size = 100 * 1024 * 1024 # 100 MiB
    module_end = base + size
    ranges = sorted(
        script.exports_sync.memory_ranges(hex(base), size),
        key=lambda memory_range: int(memory_range["base"], 16),
    )

    with open(dump_name, "wb") as f:
        cursor = base
        part = 0

        for memory_range in ranges:
            mapped_start = int(memory_range["base"], 16)
            range_start = max(mapped_start, base)
            range_end = min(mapped_start + memory_range["size"], module_end)

            if range_end <= cursor:
                continue

            if range_start > cursor:
                gap_size = range_start - cursor
                print("skipping unmapped %s+%x" % (hex(cursor), gap_size))
                write_zeros(f, gap_size)
                cursor = range_start

            range_start = max(range_start, cursor)
            range_size = range_end - range_start
            protection = memory_range["protection"]

            if not protection.startswith("r"):
                print("skipping %s %s+%x" % (protection, hex(range_start), range_size))
                write_zeros(f, range_size)
                cursor = range_end
                continue

            while range_size > 0:
                read_size = min(range_size, max_block_size)
                print("reading part %d %s+%x" % (part, hex(range_start), read_size))
                data = script.exports_sync.dump_memory(hex(range_start), read_size)
                if data is None:
                    print("mapping became inaccessible; zero-filling %s+%x" %
                          (hex(range_start), read_size))
                    write_zeros(f, read_size)
                else:
                    f.write(data)
                part += 1
                range_start += read_size
                range_size -= read_size

            cursor = range_end

        if cursor < module_end:
            gap_size = module_end - cursor
            print("skipping unmapped %s+%x" % (hex(cursor), gap_size))
            write_zeros(f, gap_size)
