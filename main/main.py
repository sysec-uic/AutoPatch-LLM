import subprocess
import openai
from openai import OpenAI
import os

afl_compiler_path = "../afl-2.52b/afl-gcc"
afl_fuzzer_path = "../afl-2.52b/afl-fuzz"
bugLog_path = "bugLog/"
codebase_path = "codebase/"
executables_path = "executables/"
executables_afl_path = "executables_afl/"
input_path = "input/"
patched_codes_path = "patched_codes/"

def run_sanitizer(program_path, isCodebase=True):
    # Compile the file and get the sanitizer result
    executable_name = program_path[:-2]
    # -O1 recommended with ASan to reduce false positives
    warnings = "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align -Wstrict-overflow -fstack-protector-strong"
    if isCodebase:
        command = f"gcc {codebase_path}{program_path} {warnings} -O1 -fsanitize=address -g -o {executables_path}{executable_name}"
    else:
        command = f"gcc {patched_codes_path}{program_path} {warnings} -O1 -fsanitize=address -g -o {executables_path}{executable_name}"
    try:
        result = subprocess.run(
            [command],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=10,
            shell=True
        )
    except Exception as e:
        print(f"Error: {e}")
    
    log = result.stdout + result.stderr

    # Check if the given code was syntactically correct
    ret = os.path.isfile(f"executables/{executable_name}")
    if ret:
        # Save the sanitizer result in the bug log
        command = f"echo \"{log}\" > {bugLog_path}{executable_name}.txt"
        try:
            result = subprocess.run(
                [command],
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=True,
                timeout=10,
                shell=True
            )
        except Exception as e:
            print(f"Error: {e}")
    
    return ret, log

def run_fuzzer(program_path, isCodebase=True):
    # Compile the file for the fuzzer
    executable_name = program_path[:-2]
    if isCodebase:
        command = f"{afl_compiler_path} {codebase_path}{program_path} -o {executables_afl_path}{executable_name}.afl"
    else:
        command = f"{afl_compiler_path} {patched_codes_path}{program_path} -o {executables_afl_path}{executable_name}.afl"
    try:
        result = subprocess.run(
            [command],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=10,
            shell=True
        )
    except Exception as e:
        print(f"Error: {e}")
    
    # Run the fuzzer to get the crashes
    command = f"{afl_fuzzer_path} -i {input_path} -o output_{executable_name}/ ./{executables_afl_path}{executable_name}.afl"
    try:
        result = subprocess.run(
            [command],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=5,
            shell=True
        )
    except subprocess.TimeoutExpired:
        return
    except Exception as e:
        print(f"Error: {e}")

def extract_crashes(code_name):
    output_path = f"output_{code_name}/crashes/"
    crashes = []

    for crash_file in os.listdir(output_path):
        if crash_file == "README.txt":
            continue
        
        file_path = os.path.join(output_path, crash_file)
        with open(file_path, 'rb') as file:
            crashes.append(file.read())
    
    return crashes

def run_file(executable_path, input, inputFromFile=False):
    executable_name = f"./{executables_path}{executable_path}"
    if inputFromFile:
        # If the program takes input from a file
        command = f"{executable_name} input"
        try:
            result = subprocess.run(
                [command],
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=True,
                timeout=10,
                shell=True
            )
            return result.stderr
        except Exception as e:
            print(f"Error: {e}")
            return "Error"
    else:
        # If the program takes input from stdin
        command = f"echo '{input}' | {executable_name}"
        try:
            result = subprocess.run(
                [command],
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=True,
                timeout=10,
                shell=True
            )
            return result.stderr
        except Exception as e:
            print(f"Error: {e}")
            return "Error"

def ask_llm_for_patch(client, code, sanitizer_output=None, crashes=None):
    if crashes is not None:
        crashes_list = "\n".join([repr(c) for c in crashes])
    prompt = f"Here's a piece of code: \n{code}\n\n"
    if crashes is not None:
        prompt += f"""The sanitizer detected this issues: \n{sanitizer_output}
        The fuzzer detected some crashes, here are some input that caused the crashes: \n{crashes_list}\n\n"""
    prompt += "Please provide a patch to fix this issue."
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
    #return ""

def main():
    # Set up the APIs
    client = OpenAI(api_key=os.environ["OPEN_API_KEY"])

    # Set up the folders
    os.makedirs(bugLog_path, exist_ok=True)
    os.makedirs(executables_path, exist_ok=True)
    os.makedirs(executables_afl_path, exist_ok=True)
    os.makedirs(patched_codes_path, exist_ok=True)

    # Clear old files
    command = f"rm -rf {bugLog_path}* {executables_path}* {executables_afl_path}* output* {patched_codes_path}*"
    try:
        result = subprocess.run(
            [command],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=10,
            shell=True
        )
    except Exception as e:
        print(f"Error: {e}")

    # Analyze the basecode
    for code in os.listdir(codebase_path):
        isCodebase = True
        
        code_name = code[:-2]
        res, log = run_sanitizer(code)
        with open(f"{codebase_path}{code}", 'r') as file:
            content_code = file.read()
        
        while True:
            print(f"Analyzing code: {code} ...")
            if res: # The code is syntactically correct, so an executable file exists for it
                run_fuzzer(code, isCodebase)
                crashes_inputs = extract_crashes(code_name)
                reply = ask_llm_for_patch(client, content_code, log, crashes_inputs)
            else: # The code is not syntactically correct, so we just give gpt the original code without any additional information
                reply = ask_llm_for_patch(client, content_code)
            
            try:
                patched_code = reply.split("```c")[1].split("```")[0].strip()
            except Exception as e:
                print(f"Error: {e}")
                patched_code = ""
            
            # Save patched code
            with open(f"{patched_codes_path}{code}", "w") as file:
                file.write(patched_code)
            content_code = patched_code
            
            print(f"Patched code for {code} created")
            isCodebase = False

            # Test patched code
            print(f"Testing code: {code} ...")
            hasCrashed = False
            if res:
                res, log = run_sanitizer(code, isCodebase)
                for crash in crashes_inputs:
                    output = run_file(code[:-2], crash)
                    if output != "":
                        hasCrashed = True

                        # Add crash info to bugLog file
                        command = f"echo \"{output}\" >> {bugLog_path}{code_name}.txt"
                        try:
                            result = subprocess.run(
                                [command],
                                stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                universal_newlines=True,
                                timeout=10,
                                shell=True
                            )
                        except Exception as e:
                            print(f"Error: {e}")
            else:
                print("No crashes detected") # Fix the fact that we have no crashes to use for testing
            
            if not hasCrashed:
                print(f"Patched code for {code} correctly working")
                break
            else:
                print(f"Patched code for {code} not properly working")


if __name__ == "__main__":
    main()
