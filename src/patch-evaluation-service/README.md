# Patch Evaluation Service

### Evaluation metric
This service evaluates the success of a patch by the following metric:

**Potential patch success:** the patch addresses all of the trigger inputs of the original code identified by the fuzzer.

**Partial potential patch success:** the patch addresses at least 80% of the trigger inputs of the original code identified by the fuzzer.

**Patch failure:** the patch fails to address at least 80% of the trigger inputs of the original code identified by the fuzzer.


### Trigger input addressment metric
A trigger is deemed addressed or not addressed by the following metric:

**Addressed:** a trigger input is said to be addressed by the patch when use of this input for the patch results in a return code of 0 (normal execution) or 1 (usually indicates that a program-handled issue occurred: different from a crash).

**Not addressed:** a trigger input is said to be unaddressed by the patch if use of this input for the patch results in a return code of >1, indicating that there was an interrupt during execution (a crash).

## How to use
Use Task to run the task **run autopatch-patch-evaluation-service**.
Use of dockerfile upcoming.

### Config files
- config.json (for use when dockerfile set up) and dev-config.json have paths to the necessary inputs: the patched code and the input json files (to be updated to CrashDetail objects)

- Ensure the `PATCH_EVAL_SVC_CONFIG` env var is set.  You may remove the "example" suffix from `/src/patch-evaluation-service/.env.example` remove the "example suffix" and set the appvar contained within `PATCH_EVAL_SVC_CONFIG` to point to the above "config.json" and source the file into your environment to use.

### Interpreting results
The results of the evaluation are stored in the subdirectory **data/timestamp** where timestamp is the time of this run of the service.

For each patch being evaluated, the service will make a csv **<executable_name>.csv**. This file lists each trigger input and the return code that it produced.

For each execution of the service, two batched information files are created:

- **evaluation.csv:** outlines the success of each patch with less detail, listing their trigger addressment rate and their metric designation (S, P, or F).
- **evaluation.md:** outlines the above information in a human readable markdown file.

### Imminent updates
- dockerfile
- update to using the CrashDetail object
- mqtt
- take input from output of patching service
- create batched results csv (headers: executable name, # triggers addressed, # triggers failed to address, success %, success designation [S, P, F])
- testing suite
  

