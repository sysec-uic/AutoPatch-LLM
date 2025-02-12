import os
import re
import subprocess
import sys

EXECUTABLES_PATH = os.environ.get(
    "EXECUTABLES_PATH", "workspace/AutoPatch-LLM/src/executables/"
)

PATCHED_CODES_PATH = os.environ.get(
    "PATCHED_CODES_PATH", "workspace/AutoPatch-LLM/src/patched_codes/"
)

EVAL_COMMAND_LOG_PATH = os.environ.get(
    "EVAL_COMMAND_LOG_PATH",
    "/workspace/AutoPatch-LLM/src/evaluation_service/command_log/",
)
OUTPUT_PATH = os.environ.get("OUTPUT_PATH", "/workspace/AutoPatch-LLM/src/output_")
RESULTS_PATH = os.environ.get(
    "RESULTS_PATH", "/workspace/AutoPatch-LLM/src/evaluation_service/results/"
)
COMPILE_TIMEOUT = 10
RUN_TIMEOUT = 10


def log_command(command: str, command_type: str, file_name: str):
    if command_type == "COMPILE":
        with open(f"{EVAL_COMMAND_LOG_PATH}{file_name}.txt", "w") as log_file:
            log_file.write("COMPILE COMMAND:\n")
            log_file.write(command + "\n")
    elif command_type == "RUN":
        with open(f"{EVAL_COMMAND_LOG_PATH}{file_name}.txt", "a") as log_file:
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
            check=True,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=RUN_TIMEOUT,
            shell=True,
        )
        return 0
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return 1
        return e.returncode
    except Exception as e:
        print(f"Error during run: {e}")
        return -1
    finally:
        log_command(command, "RUN", executable_name)


# to get the crashes: OUTPUTPATH_{executable_name}/crashes
def run_crashes(executable_path: str, file_name: str) -> dict:
    results = list()

    executable_name = file_name.split(".")[0]
    # this eventually needs to be updated
    input_from_file = False
    crash_path = OUTPUT_PATH + executable_name + "/crashes/"
    for input_file in os.listdir(crash_path):
        # need to make option for file input
        if input_file == "README.txt":
            continue
        signal_pattern = r"sig:(\d+)"

        # Using re.search to find the match
        match = re.search(signal_pattern, input_file)

        if match:
            # Extracting the matched number (group 1)
            source_sig_value = match.group(1)

        patch_sig_value = run_file(
            executable_path, executable_name, crash_path, input_file, input_from_file
        )
        if patch_sig_value == 0 or patch_sig_value == 1:
            results.append((input_file, source_sig_value, patch_sig_value, "success"))
        else:
            results.append((input_file, source_sig_value, patch_sig_value, "failure"))
    return results


def log_results(executable_path: str, file_name: str, results: list):
    log_path = RESULTS_PATH + file_name.split(".")[0] + ".txt"

    num_patched = len([crash for crash in results if crash[2] == 0 or crash[2] == 1])

    # Column names
    columns = ["input_name", "source_signal", "patch_signal", "outcome"]

    # Determine maximum width for each column (including column names)
    col_widths = [
        max(len(str(item)) for item in column) for column in zip(*results, columns)
    ]

    # Open a file to write the log
    with open(f"{log_path}", "w") as log_file:
        # Write header
        log_file.write(f"RESULTS for {executable_path}:\n\n")
        header = " | ".join(
            f"{col.ljust(width)}" for col, width in zip(columns, col_widths)
        )
        log_file.write(header + "\n")
        log_file.write("-" * len(header) + "\n")

        # Write data rows
        for row in results:
            row_line = " | ".join(
                f"{str(cell).ljust(width)}" for cell, width in zip(row, col_widths)
            )
            log_file.write(row_line + "\n")
        log_file.write(
            f"\nNumber of patched crashes: {num_patched} out of {len(results)} original crashes."
        )


# go into the patched codes folder
# compile each patched code and match it up to the designated output folder
# run on each of the inputs
# compile results into file
def main():
    os.makedirs(EXECUTABLES_PATH, exist_ok=True)
    os.makedirs(EVAL_COMMAND_LOG_PATH, exist_ok=True)
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
