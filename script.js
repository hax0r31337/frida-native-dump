rpc.exports = {
    moduleInfo: function (so_name) {
        var info = Process.findModuleByName(so_name);
        if (info == null) {
            return -1;
        }
        return info;
    },
    dumpMemory: function (base, size) {
        var p = ptr(base);
        Memory.protect(p, size, 'rwx');
        return p.readByteArray(size);
    }
}