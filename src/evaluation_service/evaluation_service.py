import os
import subprocess
import sys

EXECUTABLES_PATH = os.environ.get(
    "EXECUTABLES_PATH", "workspace/AutoPatch-LLM/src/executables/"
)

PATCHED_CODES_PATH = os.environ.get(
    "PATCHED_CODES_PATH", "workspace/AutoPatch-LLM/src/patched_codes/"
)

COMMAND_LOG_PATH = os.environ.get(
    "COMMAND_LOG_PATH", "/workspace/AutoPatch-LLM/src/command_log/"
)
OUTPUT_PATH = os.environ.get("OUTPUT_PATH", "/workspace/AutoPatch-LLM/src/output_")
RESULTS_PATH = os.environ.get(
    "RESULTS_PATH", "/workspace/AutoPatch-LLM/src/evaluation_service/results/"
)
COMPILE_TIMEOUT = 10
RUN_TIMEOUT = 10


def log_command(command: str, command_type: str, file_name: str):
    if command_type == "COMPILE":
        with open(f"{COMMAND_LOG_PATH}{file_name}.txt", "w") as log_file:
            log_file.write("COMPILE COMMAND:\n")
            log_file.write(command + "\n")
    elif command_type == "RUN":
        with open(f"{COMMAND_LOG_PATH}{file_name}.txt", "a") as log_file:
            log_file.write("RUN COMMAND:\n")
            log_file.write(command + "\n")


def compile(file_path: str, file_name: str):
    warnings = "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align -Wstrict-overflow -fstack-protector-strong"
    executable_name = file_name.split(".")[0]
    command = f"gcc {file_path} {warnings} -O1 -fsanitize=address -g -o {EXECUTABLES_PATH}{executable_name}"

    try:
        result = subprocess.run(
            [command],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=COMPILE_TIMEOUT,
            shell=True,
        )
    except Exception as e:
        print(f"Error during compilation: {e}")
    finally:
        log_command(command, "COMPILE", executable_name)
        if os.path.exists(f"{EXECUTABLES_PATH}{executable_name}"):
            print(f"Executable '{EXECUTABLES_PATH}{executable_name}' exists.")
            return f"{EXECUTABLES_PATH}{executable_name}"
        else:
            print(
                f"Compilation for '{EXECUTABLES_PATH}{executable_name}' failed. No executable made."
            )
            return ""


# fail if standard error?
def run_file(
    executable_path: str,
    executable_name: str,
    crash_path: str,
    crash: str,
    input_from_file: bool,
):
    if input_from_file:  # The program takes input from file
        command = f"{executable_path} {crash_path}{crash}"
    else:  # The program takes input from stdin
        command = f"cat {crash_path}{crash} | {executable_path}"

    try:
        result = subprocess.run(
            [command],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=RUN_TIMEOUT,
            shell=True,
        )
        return result.stderr
    except Exception as e:
        print(f"Error during run: {e}")
    finally:
        log_command(command, "RUN", executable_name)


# to get the crashes: OUTPUTPATH_{executable_name}/crashes
def run_crashes(executable_path: str, file_name: str) -> dict:
    run_results = dict()
    executable_name = file_name.split(".")[0]
    print(executable_path)
    if executable_name[-2:] == "_f":
        input_from_file = True
    else:
        input_from_file = False
    crash_path = OUTPUT_PATH + executable_name + "/crashes/"
    for crash in os.listdir(crash_path):
        # need to make option for file input
        if crash == "README.txt":
            continue
        err = run_file(
            executable_path, executable_name, crash_path, crash, input_from_file
        )
        print(err)
        if err == "":
            run_results[crash] = 0
        else:
            run_results[crash] = 1
    return run_results


def log_results(executable_path: str, file_name: str, results: dict):
    log_path = RESULTS_PATH + file_name.split(".")[0] + ".txt"
    patched_crashes = [crash for crash in results.keys() if results[crash] == 0]
    num_patched = len(patched_crashes)
    patched_crashes = "\n".join(patched_crashes)
    remaining_crashes = [crash for crash in results.keys() if results[crash] == 1]

    num_remaining = len(remaining_crashes)
    remaining_crashes = "\n".join(remaining_crashes)
    with open(log_path, "w") as log:
        log.write(f"RESULTS for {executable_path}:\n\n")
        log.write(f"Patched crashes: {num_patched}\n")
        log.write(patched_crashes + "\n\n")
        log.write(f"Remaining crashes: {num_remaining}\n")
        log.write(remaining_crashes)


# go into the patched codes folder
# compile each patched code and match it up to the designated output folder
# run on each of the inputs
# compile results into file
def main():
    os.makedirs(EXECUTABLES_PATH, exist_ok=True)
    os.makedirs(COMMAND_LOG_PATH, exist_ok=True)
    os.makedirs(RESULTS_PATH, exist_ok=True)

    for file_name in os.listdir(PATCHED_CODES_PATH):
        file_path = os.path.join(PATCHED_CODES_PATH, file_name)
        executable_path = compile(file_path, file_name)
        if executable_path == "":
            continue
        else:
            results = run_crashes(executable_path, file_name)
            log_results(executable_path, file_name, results)
    return 0


if __name__ == "__main__":
    main()
