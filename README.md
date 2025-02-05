# CS487 Final Project
# AutoPatch: Automated Vulnerable Code Patching with AFL, ASan and GPT

## Introduction  
AutoPatch is a GenAI-assisted tool designed to automatically detect and patch bugs in C code. By combining **Google's Address Sanitizer (ASan)**, **American Fuzzy Lop (AFL)** and **OpenAI's GPT-4o mini**, AutoPatch simplifies the debugging process by identifying and resolving syntactic, runtime and semantic errors in buggy programs.

### Features  
- **Automated Bug Detection:** detects and identifies syntactic errors, runtime crashes and semantic inconsistencies.  
- **Patch Generation:** uses GPT to generate targeted fixes while preserving the program's intended functionality.  
- **Iterative Testing:** retests patched code to ensure bugs are resolved.

## How It Works
1. **Initial Compilation:**  
   The code is compiled with ASan to detect memory-related issues.  
2. **Fuzzing:**  
   AFL tests the program for runtime crashes using mutated inputs.  
3. **Patching with GPT:**  
   Issues detected by ASan and AFL are passed to GPT-4o mini, which generates fixes.  
4. **Iterative Process:**  
   The patched code is retested with AFL to ensure reliability.  

## How to Run
2. Clone the repository.  
3. Run the script:
   ```bash
   python3 main/main.py
   ```

## Logging

- Automatically generates separate log directories and files for the ASan compiler output (asan_bugLog) and AFL compiler output (afl_bugLog).
Example of afl_bugLog/vulnerable.txt:
![afl_buglog_vulnerable_log_example](./docs/images/afl_buglog_vulnerable_log_example.jpeg)

- Automatically logs commands executed during the running of the service in the command_logs directory. This is very useful for troubleshooting errors in the main service execution.
![command_log_vulnerable_log](./docs/images/command_log_vulnerable_log.jpeg)
