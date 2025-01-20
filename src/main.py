import subprocess
from openai import OpenAI
import os

# Global variables for folders/files paths
afl_compiler_path = "../afl-2.52b/afl-clang"
afl_fuzzer_path = "../afl-2.52b/afl-fuzz"
bugLog_path = "bugLog/"
codebase_path = "codebase/"
executables_path = "executables/"
executables_afl_path = "executables_afl/"
input_path = "input/"
patched_codes_path = "patched_codes/"
no_stack_protector = "-fno-stack-protector"
command_log_path = "command_log/"


# Other global variables
max_tries = 3 # Maximum number of GPT queries per code
timeout = 150

def log_command(exec_name, command, command_type):
    if command_type == "asan":
        with open(f"{command_log_path}{exec_name}_log.txt", "w") as log:
            log.write("ASan Command: \n")
            log.write(command + "\n")
    elif command_type == "fuzz_compile":
        with open(f"{command_log_path}{exec_name}_log.txt", "a") as log:
            log.write("Fuzzer compile command: \n")
            log.write(command + "\n")
    elif command_type == "fuzz_run":
        with open(f"{command_log_path}{exec_name}_log.txt", "a") as log:
            log.write("Fuzzer run command: \n")
            log.write(command + "\n")



# Compile the code and save the sanitizer information in the bugLog
def run_sanitizer(program_path, isCodebase=True):
    executable_name = program_path[:-2]

    warnings = "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align -Wstrict-overflow -fstack-protector-strong"
    if isCodebase: # Source file is in the codebase
        command = f"gcc {codebase_path}{program_path} {warnings} -O1 -fsanitize=address -g -o {executables_path}{executable_name}"
    else: # Source file is a patched code
        command = f"gcc {patched_codes_path}{program_path} {warnings} -O1 -fsanitize=address -g -o {executables_path}{executable_name}"
    try:
        result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeout, shell=True)
    except Exception as e:
        print(f"Error: {e}")
    
    log_command(executable_name, command, "asan")
    # Save the outputs and errors
    log = result.stdout + result.stderr

    # Save the sanitizer output in the bugLog
    ret = os.path.isfile(f"executables/{executable_name}")
    if ret: # Check if the given code was syntactically correct (meaning it produced an executable file)
        command = f"echo \"{log}\" > {bugLog_path}{executable_name}.txt"
        try:
            result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeout, shell=True)
        except Exception as e:
            print(f"Error: {e}")
    
    return ret, log

# Compile the code for the fuzzer and run it
def run_fuzzer(program_path, timeout_fuzzer, inputFromFile, isCodebase=True):

    executable_name = program_path[:-2]

    # compile the afl execuatables
    if isCodebase: # Source file is in the codebase
        command = f"{afl_compiler_path} {no_stack_protector} {codebase_path}{program_path} -o {executables_afl_path}{executable_name}.afl"
    else: # Source file is a patched code
        command = f"{afl_compiler_path} {no_stack_protector} {patched_codes_path}{program_path} -o {executables_afl_path}{executable_name}.afl"
    try:
        result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeout, shell=True)
    except Exception as e:
        print(f"Error: {e}")
    
    log_command(executable_name, command, "fuzz_compile")
    
    if inputFromFile:
        command = f"{afl_fuzzer_path} -i {input_path} -o output_{executable_name}/ -t {timeout_fuzzer} ./{executables_afl_path}{executable_name}.afl @@"
    else:
        command = f"{afl_fuzzer_path} -i {input_path} -o output_{executable_name}/ -t {timeout_fuzzer} ./{executables_afl_path}{executable_name}.afl"


    try:
        result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeout, shell=True)
    except subprocess.TimeoutExpired:
        log_command(executable_name, command, "fuzz_run")
        return False
    except Exception as e:
        print(f"Error: {e}")

    log_command(executable_name, command, "fuzz_run")
    # Check if the fuzzer started
    command = f"ls output_{executable_name}/"
    try:
        result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeout, shell=True)
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
                result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeout, shell=True)
            except Exception as e:
                print(f"Error: {e}")
                return "Error"
            
            crashes.append(f"{file_path}")
        else:
            with open(file_path, 'rb') as file:
                crashes.append(file.read())
    
    return crashes

# Run the executable with the given input
def run_file(executable_path, crash_input, inputFromFile):
    executable_name = f"./{executables_path}{executable_path}"
    if inputFromFile: # The program takes input from file
        command = f"{executable_name} {crash_input}"
    else: # The program takes input from stdin
        command = f"echo \"{crash_input}\" | {executable_name}"
    
    try:
        result = subprocess.run([command], stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, timeout=timeout, shell=True)
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
    prompt += """Please provide a patch to fix this issue. Keep it simple, but feel free to add any error checking or changes you think are necessary.
    You can remove code, but comment out the original code with an explanation of why you removed it. Provide comments explaining the changes, and why they were made."""
    
    
    # GPT APIs invocation
    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "system",
                "content": "You are a debugging robot that looks at C programs and inputs that cause the programs to crash, and provide patches for these programs."
            },
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model="gpt-4o",
    )

    return chat_completion.choices[0].message.content

# run the source code
def run_source(client, code_path, inputFromFile):
    code_name = code_path[:-2]

    # compile the code with the sanitizer
    res, log = run_sanitizer(code_path)
    with open(f"{codebase_path}{code_path}", 'r') as file:
        content_code = file.read()
    
    print(f"Analyzing source code {code_path}...")
    fuzzerStarted = False
    
    # if the code is syntactically correct
    if res: 
        print(f"Compiled {code_path}.")
        print(f"Fuzzing {code_path}...")
        # run the fuzzer
        fuzzerStarted = run_fuzzer(code_path, timeout, inputFromFile)
        crashes_inputs = extract_crashes(code_name, inputFromFile)
        # print brief results
        print(f"Number of unique crashes found in original source file {code_path}: {len(crashes_inputs)}")
        if len(crashes_inputs) == 0:
            print(f"Fuzzer found no crashes found in source file {code_path}. Proceeding with patch using static analysis.")
            crashes_inputs = None
        # query gpt for a patch with the information
        reply = ask_gpt_for_patch(client, content_code, log, crashes_inputs, inputFromFile, fuzzerStarted)
    # if the code is not syntactically correct, did not compile
    else: 
        # query gpt for a patch 
        print(f"Compilation error in original source file {code_path}.")
        reply = ask_gpt_for_patch(client, content_code)
        crashes_inputs = None

    # return the gpt response, crashes, and the original code
    return reply, crashes_inputs, content_code

# parse the gpt reply and save it to a file in the patched code folder
def parse_reply(reply, code_path):
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
    with open(f"{patched_codes_path}{code_path}", "w") as file:
        file.write(patched_code)
    content_code = patched_code
    
    # return the content of the patch
    print(f"Patch {code_path} created.")
    return content_code

# test the patch 
# DETAILS: 
# 1. as of right now, this function fuzzes the patched code, but upon finding issues it queries the gpt with the ORIGINAL code.
# this is because of the way we worked out the prompt but could definitely be changed in future
# 2. the patched code is tested by fuzzing, not using the crashes from the original source file. this can/will be updated in the future
def test_patch(client, original_code, patch_path, inputFromFile, crashes_inputs = None):
    # run the sanitizer
    code_name = patch_path[:-2]
    res, log = run_sanitizer(patch_path, isCodebase = False)

    # if it compiles
    if res:
        print(f"Compiled {patch_path}.")
        print(f"Fuzzing {patch_path}...")
        # run the fuzzer and get the crashes
        fuzzerStarted = run_fuzzer(patch_path, timeout, inputFromFile, isCodebase = False)
        crashes_inputs = extract_crashes(code_name, inputFromFile)
    # if it doesn't compile
    elif not res:
        print(f"Compilation error for {patch_path}.")
        # query for the patch
        reply = ask_gpt_for_patch(client, original_code)
        # return error code 1 and the new patch
        return 1, reply
    
    # re-add the functionality for testing previous crashes eventually
    
    # if the patch did not generate any crashes return success 0 
    if len(crashes_inputs) == 0:
        print("Patch successful!")
        return 0, ""
    # upon failure
    else:
        print("Patch failure.")
        # check if we have reached the max tries for this code
        
        # try again by prompting gpt and return error code 1 and the reply
        reply = ask_gpt_for_patch(client, original_code, log, crashes_inputs, inputFromFile, fuzzerStarted)
        return 1, reply
        
def main():
 
    # Set up the APIs
    client = OpenAI(api_key=os.environ["OPEN_API_KEY"])

    # Set up the folders
    os.makedirs(bugLog_path, exist_ok=True)
    os.makedirs(executables_path, exist_ok=True)
    os.makedirs(executables_afl_path, exist_ok=True)
    os.makedirs(patched_codes_path, exist_ok=True)
    os.makedirs(command_log_path, exist_ok = True)

    
    # fuzz!
    for code_path in os.listdir(codebase_path):
        # get executable name and inputFromFile option
        original_file_name = code_path
        code_name = code_path[:-2]
        inputFromFile = False if code_name[-2:] != '_f' else True

        # first round of ASan, fuzzing, and gpt prompting for the source code
        gpt_response, crashes, original_code = run_source(client, code_path, inputFromFile)
        
        # start saving and testing the patches
        continuePatching = True
        patch_num = 1
        while(continuePatching):
            # save the patch as a file
            code_path = f"{code_name}_{patch_num}{code_path[-2:]}"
            patch = parse_reply(gpt_response, code_path)
            # test the patch with ASan and fuzzer
            patch_result, gpt_response = test_patch(client, original_code, code_path, inputFromFile, crashes)
            # act on the results
            if patch_result == 0:
                # success
                break
            elif patch_result == 1:
                # if max tries reached then shut down
                if patch_num == max_tries:
                    print(f"Reached maximum number of tries for {original_file_name}.")
                    break
                # else try again
                patch_num += 1


if __name__ == "__main__":
    main()
