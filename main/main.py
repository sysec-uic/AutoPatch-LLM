import subprocess
from openai import OpenAI
import os

# Global variables for folders/files paths
afl_compiler_path = "../afl-2.52b/afl-gcc"
afl_fuzzer_path = "../afl-2.52b/afl-fuzz"
bugLog_path = "bugLog/"
codebase_path = "codebase/"
executables_path = "executables/"
executables_afl_path = "executables_afl/"
input_path = "input/"
patched_codes_path = "patched_codes/"

# Other global variables
max_tries = 3 # Maximum number of GPT queries per code
timeouts = [30, 60, 120] # Increasing timeouts so that it's more likely to find crashes on complex codes

# Compile the code and save the sanitizer information in the bugLog
def run_sanitizer(program_path, isCodebase=True):
    executable_name = program_path[:-2]

    warnings = "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align -Wstrict-overflow -fstack-protector-strong"
    if isCodebase: # Source file is in the codebase
        command = f"gcc {codebase_path}{program_path} {warnings} -O1 -fsanitize=address -g -o {executables_path}{executable_name}"
    else: # Source file is a patched code
        command = f"gcc {patched_codes_path}{program_path} {warnings} -O1 -fsanitize=address -g -o {executables_path}{executable_name}"

    try:
        result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeouts[0], shell=True)
    except Exception as e:
        print(f"Error: {e}")
    
    # Save the outputs and errors
    log = result.stdout + result.stderr

    # Save the sanitizer output in the bugLog
    ret = os.path.isfile(f"executables/{executable_name}")
    if ret: # Check if the given code was syntactically correct (meaning it produced an executable file)
        command = f"echo \"{log}\" > {bugLog_path}{executable_name}.txt"
        try:
            result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeouts[0], shell=True)
        except Exception as e:
            print(f"Error: {e}")
    
    return ret, log

# Compile the code for the fuzzer and run it
def run_fuzzer(program_path, timeout_fuzzer, inputFromFile, isCodebase=True):
    print(f"Searching {program_path} for crashes...")

    executable_name = program_path[:-2]

    if isCodebase: # Source file is in the codebase
        command = f"{afl_compiler_path} {codebase_path}{program_path} -o {executables_afl_path}{executable_name}.afl"
    else: # Source file is a patched code
        command = f"{afl_compiler_path} {patched_codes_path}{program_path} -o {executables_afl_path}{executable_name}.afl"
    
    try:
        result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeouts[0], shell=True)
    except Exception as e:
        print(f"Error: {e}")
    
    # Run the fuzzer to get the crashes
    if inputFromFile:
        command = f"rm -rf output_{executable_name}/; {afl_fuzzer_path} -i {input_path} -o output_{executable_name}/ -t {timeout_fuzzer} ./{executables_afl_path}{executable_name}.afl @@"
    else:
        command = f"rm -rf output_{executable_name}/; {afl_fuzzer_path} -i {input_path} -o output_{executable_name}/ -t {timeout_fuzzer} ./{executables_afl_path}{executable_name}.afl"
    
    try:
        result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeouts[0], shell=True)
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        print(f"Error: {e}")

    # Check if the fuzzer started
    command = f"ls output_{executable_name}/"
    try:
        result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeouts[0], shell=True)
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        print(f"Error: {e}")
    
    if "fuzzer_stats" in result.stdout:
        return True
    return False

# Extract the intputs that caused any crashes during the fuzzer execution
def extract_crashes(code_name, inputFromFile):
    output_path = f"output_{code_name}/crashes/"
    
    crashes = []
    for crash_file in os.listdir(output_path):
        if crash_file == "README.txt":
            continue
        
        file_path = os.path.join(output_path, crash_file)

        # Open and retrieve crash file input
        if inputFromFile:
            # Convert the crash to utf-8 to solve issues in opening the file
            command = f"iconv -f ISO-8859-1 -t UTF-8 '{file_path}' > '{file_path}'"
            try:
                result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeouts[0], shell=True)
            except Exception as e:
                print(f"Error: {e}")
                return "Error"
            
            crashes.append(f"{file_path}")
        else:
            with open(file_path, 'rb') as file:
                crashes.append(file.read())
    
    return crashes

# Run the executable with the given input
def run_file(executable_path, input, inputFromFile):
    executable_name = f"./{executables_path}{executable_path}"

    if inputFromFile: # The program takes input from file
        command = f"{executable_name} {input}"
    else: # The program takes input from stdin
        command = f"echo \"{input}\" | {executable_name}"
    
    try:
        result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeouts[0], shell=True)
        return result.stderr
    except Exception as e:
        print(f"Error: {e}")
        return "Error"

# Query GPT to get a patched code also providing the sanitizer information and the inputs that caused any crash
def ask_gpt_for_patch(client, code, sanitizer_output=None, crashes=None, inputFromFile=None, fuzzerStarted=None):
    # Check if any crash was provided
    if crashes is not None:
        if inputFromFile:
            crashes_list = "\n".join([open(c, 'r').read() for c in crashes])
        else:
            crashes_list = "\n".join([repr(c) for c in crashes])
    
    # Prepare prompt
    prompt = f"Here's a piece of code: \n{code}\n"
    if sanitizer_output is not None:
        prompt += f"The sanitizer detected this issues: \n{sanitizer_output}\n"
    if crashes is not None:
        prompt += f"The fuzzer detected some crashes, here are some inputs that caused the crashes: \n{crashes_list}\n\n"""
    if not fuzzerStarted and fuzzerStarted is not None:
        prompt += "The code crashes regardless of the input it is given."
    prompt += """Please provide a patch to fix this issue. Don't change the meaning at all, keep it simple, don't add
        any comments and solve the issues in the easiest possible way"""
    
    # GPT APIs invocation
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
    os.makedirs(bugLog_path, exist_ok=True)
    os.makedirs(executables_path, exist_ok=True)
    os.makedirs(executables_afl_path, exist_ok=True)
    os.makedirs(patched_codes_path, exist_ok=True)

    # Clear old files
    command = f"rm -rf {bugLog_path}* {executables_path}* {executables_afl_path}* output* {patched_codes_path}*"
    try:
        result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeouts[0], shell=True)
    except Exception as e:
        print(f"Error: {e}")

    # Analyze the basecode
    for code in os.listdir(codebase_path):
        isCodebase = True

        # Extract input type
        code_name = code[:-2]
        inputFromFile = False if code_name[-2:] != '_f' else True

        # Compile the code
        res, log = run_sanitizer(code)
        with open(f"{codebase_path}{code}", 'r') as file:
            content_code = file.read()
        
        # Loop either until a working patched code is provided or the max number of queries is reached
        print(f"Analyzing code: {code} ...")
        fuzzerStarted = False
        for _ in range(max_tries):
            # Run fuzzer and extract crashes
            if res: # The code is syntactically correct, so an executable file exists for it
                fuzzerStarted = run_fuzzer(code, timeouts[0], inputFromFile, isCodebase)
                crashes_inputs = extract_crashes(code_name, inputFromFile)
                reply = ask_gpt_for_patch(client, content_code, log, crashes_inputs, inputFromFile, fuzzerStarted)
            else: # The code is not syntactically correct, so we just give gpt the original code without any additional information
                reply = ask_gpt_for_patch(client, content_code)
            
            # Parse the GPT reply
            try:
                if "```" in reply:
                    patched_code = reply.split("```c")[1].split("```")[0].strip()
                else:
                    print("Error")
            except Exception as e:
                print(f"Error: {e}")
                patched_code = ""
            
            # Save patched code
            with open(f"{patched_codes_path}{code}", "w") as file:
                file.write(patched_code)
            content_code = patched_code
            
            print(f"Patched code for {code} created")
            isCodebase = False # Switch folder

            # Test patched code
            print(f"Testing code: {code} ...")
            hasCrashed = False
            if not res: # The code is not syntactically correct, so we have no crashes to use to test it
                for t in timeouts: # Run the fuzzer for increasing timeouts until some crash is found
                    res, log = run_sanitizer(code, isCodebase)
                    fuzzerStarted = run_fuzzer(code, t, inputFromFile, isCodebase)
                    crashes_inputs = extract_crashes(code_name, inputFromFile)
                    if crashes_inputs: # Found some crashes
                        break
                if not res: # The code is not syntactically correct, so we have no crashes to use to test it
                    continue
            else: # The code is syntactically correct, so we have some crashes to use to test it
                # Compile the patched code
                res, log = run_sanitizer(code, isCodebase)
            
            for crash in crashes_inputs:
                output = run_file(code[:-2], crash, inputFromFile)
                if output != "":
                    hasCrashed = True

                    # Save the crash info in the bugLog
                    command = f"echo \"{output}\" >> {bugLog_path}{code_name}.txt"
                    try:
                        result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeouts[0], shell=True)
                    except Exception as e:
                        print(f"Error: {e}")
            
            if not hasCrashed:
                print(f"Patched code for {code} correctly working")
                break
            else:
                print(f"Patched code for {code} not properly working")

        print(f"{code} patched!\n")

    print("Code analysis finished!")


if __name__ == "__main__":
    main()
