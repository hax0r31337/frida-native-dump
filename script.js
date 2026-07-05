rpc.exports = {
    moduleInfo: function (so_name) {
        var info = Process.findModuleByName(so_name);
        if (info == null) {
            return -1;
        }
        return info;
    },
    memoryRanges: function (base, size) {
        var start = ptr(base);
        var end = start.add(size);

        return Process.enumerateRanges({ protection: '---', coalesce: false })
            .filter(function (range) {
                var rangeEnd = range.base.add(range.size);
                return range.base.compare(end) < 0 && rangeEnd.compare(start) > 0;
            })
            .map(function (range) {
                return {
                    base: range.base.toString(),
                    size: range.size,
                    protection: range.protection
                };
            });
    },
    dumpMemory: function (base, size) {
        var p = ptr(base);
        try {
            return p.readByteArray(size);
        } catch (e) {
            // A mapping can change between enumeration and reading. Let the
            // host preserve this portion of the image with zero-filled bytes.
            return null;
        }
    }
}
