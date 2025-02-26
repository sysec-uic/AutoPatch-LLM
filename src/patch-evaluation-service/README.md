## Patch Evaluation Service

### Function
This service evaluates the success of a patch by the following metric:

**Potential patch success:** the patch addresses all of the trigger inputs of the original code identified by the fuzzer.

**Partial potential patch success:** the patch addresses at least 80% of the trigger inputs of the original code identified by the fuzzer.

**Patch failure:** the patch fails to address at least 80% of the trigger inputs of the original code identified by the fuzzer.

### How to use
Use Task to run the task **run autopatch-patch-evaluation-service**.
Use of dockerfile upcoming.

### Config files
- config.json (for use when dockerfile set up) and dev-config.json have paths to the necessary inputs: the patched code and the input json files (to be updated to CrashDetail objects)

- Ensure the `PATCH_EVAL_SVC_CONFIG` env var is set.  You may remove the "example" suffix from `/src/patch-evaluation-service/.env.example` remove the "example suffix" and set the appvar contained within `PATCH_EVAL_SVC_CONFIG` to point to the above "config.json" and source the file into your environment to use.

### Imminent updates
- dockerfile
- update to using the CrashDetail object
- mqtt
- take input from output of patching service
- create batched results csv (headers: executable name, # triggers addressed, # triggers failed to address, success %, success designation [S, P, F])
- testing suite
  

