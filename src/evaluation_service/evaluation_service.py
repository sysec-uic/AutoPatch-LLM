import os
import re
import subprocess

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


# logs the given command in the command_log file for this code
def log_command(command: str, command_type: str, file_name: str):
    if command_type == "COMPILE":
        with open(f"{EVAL_COMMAND_LOG_PATH}{file_name}.txt", "w") as log_file:
            log_file.write("COMPILE COMMAND:\n")
            log_file.write(command + "\n")
    elif command_type == "RUN":
        with open(f"{EVAL_COMMAND_LOG_PATH}{file_name}.txt", "a") as log_file:
            log_file.write("RUN COMMAND:\n")
            log_file.write(command + "\n")


# logs the overall results of the evaluation
def log_results(executable_path: str, file_name: str, results: list):
    log_path = RESULTS_PATH + file_name.split(".")[0] + ".txt"

    # count the number of patched as those whose status code was 0 or 1
    # this might need further consideration
    num_patched = len([crash for crash in results if crash[2] == 0 or crash[2] == 1])

    # column names with file, the signal of the original code, the patch signal result, and the outcome
    columns = ["input_name", "source_signal", "patch_signal", "outcome"]

    # get the max width of the column data
    col_widths = [
        max(len(str(item)) for item in column) for column in zip(*results, columns)
    ]

    # open a file to write the log
    with open(f"{log_path}", "w") as log_file:
        # write header
        log_file.write(f"RESULTS for {executable_path}:\n\n")
        header = " | ".join(
            f"{col.ljust(width)}" for col, width in zip(columns, col_widths)
        )
        log_file.write(header + "\n")
        log_file.write("-" * len(header) + "\n")

        # write data rows
        for row in results:
            row_line = " | ".join(
                f"{str(cell).ljust(width)}" for cell, width in zip(row, col_widths)
            )
            log_file.write(row_line + "\n")
        # write overall patch success
        log_file.write(
            f"\nNumber of patched crashes: {num_patched} out of {len(results)} original crashes."
        )


# compiles the program
def compile(file_path: str, file_name: str):
    # form the command
    warnings = "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align -Wstrict-overflow -fstack-protector-strong"
    executable_name = file_name.split(".")[0]
    command = f"gcc {file_path} {warnings} -O1 -fsanitize=address -g -o {EXECUTABLES_PATH}{executable_name}"

    # run the command
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
        # move this to a log
        print(f"Error during compilation: {e}")
    finally:
        # log the command and return either the path to the executable or an empty string on failure
        log_command(command, "COMPILE", executable_name)
        if os.path.exists(f"{EXECUTABLES_PATH}{executable_name}"):
            return f"{EXECUTABLES_PATH}{executable_name}"
        else:
            return ""


# run the file with some given input
def run_file(
    executable_path: str,
    executable_name: str,
    crash_path: str,
    crash: str,
    input_from_file: bool,
):
    # form the command
    if input_from_file:  # The program takes input from file
        command = f"{executable_path} {crash_path}{crash}"
    else:  # The program takes input from stdin
        command = f"cat {crash_path}{crash} | {executable_path}"

    # run the command
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
        # return 0 on complete success
        return 0
    # if the program terminated with a signal != 0 then this exception is entered
    except subprocess.CalledProcessError as e:
        return e.returncode
    except Exception as e:
        print(f"Error during run: {e}")
        return -1
    # log the command
    finally:
        log_command(command, "RUN", executable_name)


# run a file with a batch of crashes
def run_crashes(executable_path: str, file_name: str) -> list:
    # the list to store the results
    results = list()
    executable_name = file_name.split(".")[0]
    # input from file needs to be updated eventually
    input_from_file = False

    # iterate through the crashes
    crash_path = OUTPUT_PATH + executable_name + "/crashes/"
    for input_file in os.listdir(crash_path):
        # skip the README that is created by the fuzzer
        if input_file == "README.txt":
            continue

        # extract the signal produced by running the original source code with this input
        # (the signal is in the name of the input file)
        signal_pattern = r"sig:(\d+)"
        match = re.search(signal_pattern, input_file)
        if match:
            source_sig_value = match.group(1)

        # run the patch with the input, the return value is the signal
        patch_sig_value = run_file(
            executable_path, executable_name, crash_path, input_file, input_from_file
        )
        # if the new signal is 0 or 1, then success (might change)
        # add the outcome to the results log
        if patch_sig_value == 0 or patch_sig_value == 1:
            results.append((input_file, source_sig_value, patch_sig_value, "success"))
        # otherwise, failure
        else:
            results.append((input_file, source_sig_value, patch_sig_value, "failure"))
    # return the results
    return results


def main():
    # make the directories for the executable, the command log, and the results
    os.makedirs(EXECUTABLES_PATH, exist_ok=True)
    os.makedirs(EVAL_COMMAND_LOG_PATH, exist_ok=True)
    os.makedirs(RESULTS_PATH, exist_ok=True)

    # iterate through the patched codes directory
    for file_name in os.listdir(PATCHED_CODES_PATH):
        file_path = os.path.join(PATCHED_CODES_PATH, file_name)
        # compile the file
        executable_path = compile(file_path, file_name)
        # if the executable was successfully made
        if executable_path != "":
            # run the executable with the crashes and log the results
            results = run_crashes(executable_path, file_name)
            log_results(executable_path, file_name, results)
    return 0


if __name__ == "__main__":
    main()
