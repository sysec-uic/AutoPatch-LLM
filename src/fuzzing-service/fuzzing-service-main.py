# NEEDS TESTING

# Explanation
# Logging:
# The log_command function writes each compile and run command to a per-executable
# log file inside the folder specified by COMMAND_LOG_PATH.

# Compilation with ASan:
# The run_sanitizer function compiles the source file with AddressSanitizer enabled.
# It logs the command and saves the compile output to a "buglog" file.

# Fuzzer Execution:
# The run_fuzzer function uses AFL’s compiler (specified by AFL_COMPILER_PATH) to build
# a fuzzing version of the code and then runs the fuzzer. It verifies that the fuzzer
# started by checking for the presence of a file named fuzzer_stats in the output directory.

# Crash Extraction:
# The extract_crashes function looks for crash files in the fuzzer’s output
# folder and (if needed) converts them to UTF-8 encoding before reporting.

# This refactored code now concerns itself solely with the build–fuzz–analyze cycle.
# You can integrate further logging or error handling as needed for your use case.


import json
import os
import subprocess
import sys
from dataclasses import dataclass

# Global variables for folders/files paths
AFL_COMPILER_PATH = os.environ.get("AFL_COMPILER_PATH", "../afl-2.52b/afl-gcc")
AFL_FUZZER_PATH = os.environ.get("AFL_FUZZER_PATH", "../afl-2.52b/afl-fuzz")
ASAN_BUGLOG_PATH = os.environ.get("ASAN_BUGLOG_PATH", "asan_bugLog/")
AFL_BUGLOG_PATH = os.environ.get("AFL_BUGLOG_PATH", "afl_bugLog/")
CODEBASE_PATH = os.environ.get("CODEBASE_PATH", "codebase/")
EXECUTABLES_PATH = os.environ.get("EXECUTABLES_PATH", "executables/")
EXECUTABLES_AFL_PATH = os.environ.get("EXECUTABLES_AFL_PATH", "executables_afl/")
INPUT_PATH = os.environ.get("INPUT_PATH", "input/")
COMMAND_LOG_PATH = os.environ.get("COMMAND_LOG_PATH", "command_log/")

# Other settings
no_stack_protector = "-fno-stack-protector"
timeout = 120  # seconds


@dataclass
class Config:
    mqtt_host: str
    mqtt_port: int

    fuzz_svc_input_codebase_path: str

    fuzz_svc_output_output_topic: str
    fuzz_svc_output_path: str

    svc_output_output_topic: str
    svc_output_path: str

    compiler_tool: str

    afl_tool: str
    afl_tool_output_topic: str
    afl_tool_output_path: str

    address_sanitize_tool: str
    address_sanitizer_output_topic: str
    address_sanitizer_output_path: str

    compiled_binary_executables_output_path: str
    afl_tool_compiled_binary_executables_output_path: str

    debug: bool = False


def load_config_as_json() -> dict:
    # Read the environment variable
    config_path = os.environ.get("FUZZ_SVC_CONFIG")
    if not config_path:
        print(
            "Error: The environment variable 'FUZZ_SVC_CONFIG' is not set or is empty."
        )
        sys.exit(1)

    try:
        # Open the file with UTF-8 encoding
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"Error: The config file at '{config_path}' was not found.")
        sys.exit(1)
    except UnicodeDecodeError as e:
        print(
            f"Error: The config file at '{config_path}' is not a valid UTF-8 text file: {e}"
        )
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: The config file at '{config_path}' contains invalid JSON: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: An unexpected error occurred while loading the config file: {e}")
        sys.exit(1)

    print("Config type is :")
    print(type(config))
    return config


def log_command(exec_name, command, command_type):
    """
    Log the given command to a file associated with the executable.
    """
    log_file = os.path.join(COMMAND_LOG_PATH, f"{exec_name}_log.txt")
    mode = "w" if command_type == "asan" else "a"
    with open(log_file, mode) as log:
        if command_type == "asan":
            log.write("ASan Command:\n")
        elif command_type == "fuzz_compile":
            log.write("Fuzzer compile command:\n")
        elif command_type == "fuzz_run":
            log.write("Fuzzer run command:\n")
        log.write(command + "\n")


def run_sanitizer(program_path, isCodebase=True):
    """
    Compile the given C source file with AddressSanitizer enabled.
    Returns a tuple: (True/False depending on successful compilation, compile output log).
    """
    executable_name = os.path.splitext(program_path)[0]
    warnings = (
        "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align "
        "-Wstrict-overflow -fstack-protector-strong"
    )
    if isCodebase:
        src_path = os.path.join(CODEBASE_PATH, program_path)
    else:
        src_path = program_path

    command = (
        f"gcc {src_path} {warnings} -O1 -fsanitize=address -g "
        f"-o {os.path.join(EXECUTABLES_PATH, executable_name)}"
    )
    try:
        result = subprocess.run(
            command,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
            shell=True,
        )
    except Exception as e:
        print(f"Error running sanitizer compile: {e}")
        return False, str(e)

    log_command(executable_name, command, "asan")
    log_output = result.stdout + result.stderr

    executable_file = os.path.join(EXECUTABLES_PATH, executable_name)
    if os.path.isfile(executable_file):
        # Save sanitizer log output
        buglog_path = os.path.join(ASAN_BUGLOG_PATH, executable_name + ".txt")
        buglog_command = f'echo "{log_output}" > {buglog_path}'
        try:
            subprocess.run(
                buglog_command,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=True,
                timeout=timeout,
                shell=True,
            )
        except Exception as e:
            print(f"Error saving sanitizer buglog: {e}")
        return True, log_output
    else:
        return False, log_output


def run_fuzzer(program_path, timeout_fuzzer, inputFromFile, isCodebase=True):
    """
    Compile the C source file for AFL fuzzing and run the fuzzer.
    Returns True if the fuzzer appears to have started successfully.
    """
    executable_name = os.path.splitext(program_path)[0]
    if isCodebase:
        src_path = os.path.join(CODEBASE_PATH, program_path)
    else:
        src_path = program_path

    afl_executable = os.path.join(EXECUTABLES_AFL_PATH, executable_name + ".afl")
    # Compile using AFL's compiler
    compile_command = (
        f"{AFL_COMPILER_PATH} {no_stack_protector} {src_path} -o {afl_executable}"
    )
    try:
        result = subprocess.run(
            compile_command,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
            shell=True,
        )
        # Save AFL compiler log output
        buglog_path = os.path.join(AFL_BUGLOG_PATH, executable_name + ".txt")
        with open(buglog_path, "w") as buglog:
            buglog.write(result.stdout + result.stderr)
    except Exception as e:
        print(f"Error compiling with AFL: {e}")
        return False

    log_command(executable_name, compile_command, "fuzz_compile")

    # Prepare the fuzzing command
    if inputFromFile:
        fuzz_command = (
            f"{AFL_FUZZER_PATH} -i {INPUT_PATH} -o output_{executable_name}/ "
            f"-t {timeout_fuzzer} {afl_executable} @@"
        )
    else:
        fuzz_command = (
            f"{AFL_FUZZER_PATH} -i {INPUT_PATH} -o output_{executable_name}/ "
            f"-t {timeout_fuzzer} {afl_executable}"
        )
    try:
        subprocess.run(
            fuzz_command,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            timeout=timeout,
            universal_newlines=True,
            shell=True,
        )
    except subprocess.TimeoutExpired:
        # Fuzzer may run indefinitely; timeout is expected.
        pass
    except Exception as e:
        print(f"Error running fuzzer: {e}")
        return False

    log_command(executable_name, fuzz_command, "fuzz_run")

    # Verify that the fuzzer started by checking for the "fuzzer_stats" file
    list_command = f"ls output_{executable_name}/"
    try:
        result = subprocess.run(
            list_command,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            timeout=timeout,
            universal_newlines=True,
            shell=True,
        )
    except Exception as e:
        print(f"Error listing fuzzer output: {e}")
        return False

    if "fuzzer_stats" in result.stdout:
        return True
    return False


def extract_crashes(executable_name, inputFromFile):
    """
    Examine the fuzzer output directory for crash inputs.
    Returns a list of crash file paths (if inputFromFile is True) or raw byte contents.
    """
    crash_dir = os.path.join(f"output_{executable_name}", "crashes")
    crashes = []
    try:
        for crash_file in os.listdir(crash_dir):
            if crash_file == "README.txt":
                continue
            file_path = os.path.join(crash_dir, crash_file)
            if inputFromFile:
                # Convert file encoding to UTF-8 (if necessary)
                convert_command = (
                    f"iconv -f ISO-8859-1 -t UTF-8 '{file_path}' > '{file_path}.utf8'"
                )
                try:
                    subprocess.run(
                        convert_command,
                        stderr=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        timeout=timeout,
                        universal_newlines=True,
                        shell=True,
                    )
                    os.replace(f"{file_path}.utf8", file_path)
                except Exception as e:
                    print(f"Error converting crash file encoding: {e}")
                    continue
                crashes.append(file_path)
            else:
                with open(file_path, "rb") as f:
                    crashes.append(f.read())
    except FileNotFoundError:
        print("No crashes directory found. Fuzzer might not have detected any crashes.")
    return crashes


def main():
    config = load_config_as_json()
    print("Config loaded successfully:")
    print(config)
    # Ensure required directories exist
    for directory in [
        ASAN_BUGLOG_PATH,
        AFL_BUGLOG_PATH,
        EXECUTABLES_PATH,
        EXECUTABLES_AFL_PATH,
        INPUT_PATH,
        COMMAND_LOG_PATH,
    ]:
        os.makedirs(directory, exist_ok=True)

    # Process each C source file in the codebase directory
    for source_file in os.listdir(CODEBASE_PATH):
        if not source_file.endswith(".c"):
            continue

        print(f"\n=== Processing {source_file} ===")
        executable_name = os.path.splitext(source_file)[0]
        # Optionally, decide if the target takes input from a file (e.g. based on naming convention)
        inputFromFile = executable_name.endswith("_f")

        # Step 1: Compile with AddressSanitizer
        compiled, sanitizer_log = run_sanitizer(source_file, isCodebase=True)
        if not compiled:
            print(f"ASan compilation failed for {source_file}. Skipping fuzzer run.")
            continue
        print(f"ASan compilation succeeded for {source_file}.")

        # Step 2: Run the AFL fuzzer
        fuzzer_started = run_fuzzer(
            source_file, timeout, inputFromFile, isCodebase=True
        )
        if fuzzer_started:
            print(f"Fuzzer started for {source_file}.")
        else:
            print(f"Fuzzer did not start properly for {source_file}.")

        # Step 3: Extract crash inputs (if any)
        crashes = extract_crashes(executable_name, inputFromFile)
        if crashes:
            print(f"Found {len(crashes)} crash(es) for {source_file}:")
            for crash in crashes:
                print(f"  - {crash}")
        else:
            print(f"No crashes found for {source_file}.")


if __name__ == "__main__":
    main()
