import subprocess

afl_compiler_path = "../afl-2.52b/afl-gcc"
afl_fuzzer_path = "../afl-2.52b/afl-fuzz"

def run_sanitizer(program_path):
    # Compile the file and get the sanitizer result
    executable_name = program_path[2:-2]
    # -O1 recommended with ASan to reduce false positives
    warnings = "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align -Wstrict-overflow -fstack-protector-strong"
    command = f"gcc {program_path} {warnings} -O1 -fsanitize=address -g -o executables/{executable_name}"
    result = subprocess.run(
        [command],
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        universal_newlines=True,
        timeout=10,
        shell=True
    )
    log = result.stdout + result.stderr

    # Save the sanitizer result in the bug log
    command = f"mkdir -p bugLog; echo \"{log}\" > bugLog/{executable_name}.txt"
    result = subprocess.run(
        [command],
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        universal_newlines=True,
        timeout=10,
        shell=True
    )

    print(result.stderr)

    return log

def run_fuzzer(program_path):
    # Compile the file for the fuzzer
    executable_name = program_path[2:-2]
    command = f"{afl_compiler_path} {program_path} -o executables_afl/{executable_name}.afl"
    result = subprocess.run(
        [command],
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        universal_newlines=True,
        timeout=10,
        shell=True
    )

    # Run the fuzzer to get the crashes
    #command = f"sh -c '{afl_fuzzer_path} -i input -o output ./executables_afl/{executable_name}.afl'"
    command = f"{afl_fuzzer_path} -i input -o output ./executables_afl/{executable_name}.afl"
    result = subprocess.run(
        [command],
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        universal_newlines=True,
        timeout=10,
        shell=True
    )

def run_file(executable_path, input, inputFromFile=False):
    if inputFromFile:
        # If the program takes input from a file
        result = subprocess.run(
            [executable_path, input],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=10,
            shell=True
        )
    else:
        # If the program takes input from stdin
        result = subprocess.run(
            [executable_path],
            input=input,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=10,
            shell=True
        )
    output = result.stderr + result.stdout

    # Remove the executable
    #os.remove(executable_path)

    return output

def main():
    res = run_sanitizer("./example1.c")
    res = run_fuzzer("./example1.c")
    res = run_file("./executables/example1", "Name")
    print(res)

if __name__ == "__main__":
    main()