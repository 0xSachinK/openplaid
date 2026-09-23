"""Private Wasm worker entrypoint. Only sandbox.run_adapter should launch this."""
import resource
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verification.common import canonical, require, strict_json, unb64
from verification.sandbox import MAX_INPUT, MAX_MODULE, MAX_OUTPUT


class GuestExit(Exception):
    pass


def execute(module_bytes, input_bytes):
    import wasmtime as w
    config = w.Config()
    config.consume_fuel = True
    config.parallel_compilation = False
    config.max_wasm_stack = 256 * 1024
    config.memory_reservation = 0
    config.memory_guard_size = 65536
    config.wasm_threads = False
    config.wasm_memory64 = False
    config.wasm_multi_memory = False
    engine = w.Engine(config)
    module = w.Module(engine, module_bytes)  # Never deserialize untrusted native code.
    store = w.Store(engine)
    store.set_limits(memory_size=64 * 1024 * 1024, table_elements=10000,
                     instances=1, tables=1, memories=1)
    store.set_fuel(50_000_000)
    linker = w.Linker(engine)
    output = bytearray()
    input_offset = 0
    output_bytes = 0

    def memory(caller):
        value = caller.get('memory')
        require(isinstance(value, w.Memory), 'sandbox_memory')
        return value

    def checked(caller, address, length):
        mem = memory(caller)
        require(0 <= address <= mem.data_len(caller) and 0 <= length <= mem.data_len(caller) - address,
                'sandbox_memory')
        return mem

    def write(caller, address, data):
        checked(caller, address, len(data)).write(caller, data, address)

    def vectors(caller, pointer, count):
        require(0 <= count <= 64, 'sandbox_io')
        mem = checked(caller, pointer, count * 8)
        raw = mem.read(caller, pointer, pointer + count * 8)
        return [struct.unpack_from('<II', raw, n * 8) for n in range(count)]

    def fd_read(caller, fd, pointer, count, result):
        nonlocal input_offset
        if fd != 0:
            return 8  # BADF: no other input descriptors exist.
        total = 0
        for address, length in vectors(caller, pointer, count):
            checked(caller, address, length)
            piece = input_bytes[input_offset:input_offset + length]
            write(caller, address, piece)
            input_offset += len(piece)
            total += len(piece)
        write(caller, result, struct.pack('<I', total))
        return 0

    def fd_write(caller, fd, pointer, count, result):
        nonlocal output_bytes
        if fd not in (1, 2):
            return 8
        total = 0
        for address, length in vectors(caller, pointer, count):
            mem = checked(caller, address, length)
            output_bytes += length
            require(output_bytes <= MAX_OUTPUT, 'sandbox_output_size')
            if fd == 1:
                output.extend(mem.read(caller, address, address + length))
            total += length
        write(caller, result, struct.pack('<I', total))
        return 0  # stderr is discarded but consumes the same output budget.

    def env_sizes(caller, count, size):
        write(caller, count, b'\0' * 4)
        write(caller, size, b'\0' * 4)
        return 0

    def clock(caller, clock_id, precision, result):
        write(caller, result, b'\0' * 8)  # Fixed clock, never host timing.
        return 0

    def fd_stat(caller, fd, result):
        if fd not in (0, 1, 2):
            return 8
        write(caller, result, struct.pack('<B7xQQ', 2, 2 if fd == 0 else 64, 0))
        return 0

    def exit_guest(caller, status):
        require(status == 0, 'sandbox_guest_failed')
        raise GuestExit()

    i32, i64 = w.ValType.i32(), w.ValType.i64()
    functions = {
        'fd_read': ([i32] * 4, [i32], fd_read),
        'fd_write': ([i32] * 4, [i32], fd_write),
        'environ_sizes_get': ([i32] * 2, [i32], env_sizes),
        'environ_get': ([i32] * 2, [i32], lambda caller, a, b: 0),
        'clock_time_get': ([i32, i64, i32], [i32], clock),
        'fd_fdstat_get': ([i32] * 2, [i32], fd_stat),
        'fd_close': ([i32], [i32], lambda caller, fd: 8),
        'fd_seek': ([i32, i64, i32, i32], [i32], lambda caller, *args: 70),
        'proc_exit': ([i32], [], exit_guest),
    }
    require(len(module.imports) <= len(functions), 'sandbox_imports')
    for item in module.imports:
        require(item.module == 'wasi_snapshot_preview1' and item.name in functions,
                'sandbox_imports')
    for name, (params, results, callback) in functions.items():
        linker.define_func('wasi_snapshot_preview1', name, w.FuncType(params, results),
                           callback, access_caller=True)
    try:
        instance = linker.instantiate(store, module)
        start = instance.exports(store).get('_start')
        require(isinstance(start, w.Func) and not start.type(store).params and
                not start.type(store).results, 'sandbox_entrypoint')
        start(store)
    except GuestExit:
        pass
    return strict_json(bytes(output), MAX_OUTPUT)


def main():
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.platform == 'linux':
        resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024,) * 2)
    try:
        request = strict_json(sys.stdin.buffer.read(5 * 1024 * 1024 + 1), 5 * 1024 * 1024)
        module = unb64(request['module'], MAX_MODULE)
        data = unb64(request['input'], MAX_INPUT)
        value = execute(module, data)
        sys.stdout.buffer.write(canonical({'ok': True, 'value': value}))
    except BaseException:
        sys.stdout.buffer.write(b'{"ok":false}')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
