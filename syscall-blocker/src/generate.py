import argparse

# args: --input, --output, --syscalls
parser = argparse.ArgumentParser()
parser.add_argument("--input", type=str, required=True)
parser.add_argument("--output", type=str, required=True)
parser.add_argument("--syscalls", type=str, required=True)
args = parser.parse_args()

# Read input file
with open(args.input, "r") as f:
    data = f.read()

# Parse syscalls
with open(args.syscalls, "r") as f:
    syscalls = f.read().split("\n")
syscalls = [syscall for syscall in syscalls if syscall != ""]

# Contents before // gen:start
preamble = data.split("// gen:start")[0]
epilogue = data.split("// gen:end")[1]
content = data.split("// gen:start")[1].split("// gen:end")[0]

# Generate new content
new_content = preamble
for syscall in syscalls:
    new_content += content.replace("select", syscall).replace("syscall_name", syscall)
new_content += epilogue

# Write to output file
with open(args.output, "w") as f:
    f.write(new_content)
