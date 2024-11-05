import subprocess
import openai
from openai import OpenAI
import os

afl_compiler_path = "../afl-2.52b/afl-gcc"
afl_fuzzer_path = "../afl-2.52b/afl-fuzz"

def run_sanitizer(program_path):
    # Compile the file and get the sanitizer result
    executable_name = program_path[:-2]
    # -O1 recommended with ASan to reduce false positives
    warnings = "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align -Wstrict-overflow -fstack-protector-strong"
    command = f"gcc codebase/{program_path} {warnings} -O1 -fsanitize=address -g -o executables/{executable_name}"
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

    # We could also do:
    """
        with open(log, "r") as file:
            content = file.read()
        with open(f"bugLog/{executable_name}.txt", "w") as file:
            file.write(content)
    """

    return log

def run_fuzzer(program_path):
    # Compile the file for the fuzzer
    executable_name = program_path[:-2]
    command = f"{afl_compiler_path} codebase/{program_path} -o executables_afl/{executable_name}.afl"
    result = subprocess.run(
        [command],
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        universal_newlines=True,
        timeout=10,
        shell=True
    )

    # Run the fuzzer to get the crashes
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
    executable_name = f"./executables/{executable_path}"
    if inputFromFile:
        # If the program takes input from a file
        result = subprocess.run(
            [executable_name, input],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=10,
            shell=True
        )
    else:
        # If the program takes input from stdin
        result = subprocess.run(
            [executable_name],
            input=input,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=10,
            shell=True
        )
    output = result.stderr + result.stdout

    return output

def ask_llm_for_patch(client, code, sanitizer_output):
    prompt = f"Here's a piece of code: {code}\nThe sanitizer detected this issue: {sanitizer_output}\nPlease provide a patch to fix this issue."
    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model="gpt-4o-mini",
    )
    return chat_completion.choices[0].message.content

def main():
    # Set up the APIs
    client = OpenAI(api_key=os.environ["OPEN_API_KEY"])

    # Set up the folders
    os.makedirs("bugLog", exist_ok=True)
    os.makedirs("executables", exist_ok=True)
    os.makedirs("executables_afl", exist_ok=True)
    os.makedirs("patched_codes", exist_ok=True)

    res = run_sanitizer("example1.c")
    res = run_fuzzer("example1.c")
    res = run_file("example1", "Name")
    print(res)

    with open("codebase/example1.c", 'r') as file:
        content_code = file.read()
    with open("bugLog/example1.txt", 'r') as file:
        content_sanitizer = file.read()
    reply = ask_llm_for_patch(client, content_code, content_sanitizer)
    patched_code = reply.split("```c")[1].split("```")[0].strip()

    print(f"Patched code:\n{patched_code}")

    with open("patched_codes/example1.c", "w") as file:
        file.write(patched_code)

if __name__ == "__main__":
    main()
