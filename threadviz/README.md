# **ThreadViz**

## Implementation Notes

* The program uses eBPF hooks to trace thread events.
* The user-space program transforms the raw data into Perfetto trace format.
* The trace is then visualized using Perfetto UI.

https://github.com/user-attachments/assets/02ef1524-19d6-4015-9d67-3013355e60d4

## Dependencies

- libbpf
- bpftool in $PATH
- clang
- cmake
- conan (installed and available in $PATH)

## Building

```sh
conan install . --output-folder=build --build=missing
cmake --preset conan-release
cmake --build build
```

## Running

Run the program:
```sh
sudo ./scripts/visualize.sh [-t trace_duration_ms] [-f trace_file] [-d] [-h]
```

Load the trace file into https://ui.perfetto.dev/ and visualize it.
