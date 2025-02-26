## Patch Evaluation Service

### Function
This service evaluates the success of code by the following metric:

**Potential patch success:** the patch addresses all of the trigger inputs of the original code identified by the fuzzer.

**Partial potential patch success:** the patch addresses at least 80% of the trigger inputs of the original code identified by the fuzzer.

**Patch failure:** the patch fails to address at least 80% of the trigger inputs of the original code identified by the fuzzer.

### How to use
Use Task to run the task run autopatch-patch-evaluation-service.

### Config files
- use config.json when running as a container, like with docker-compose or k8s
- use dev-config.json when running interactively inside a devcontainer, or on your local host system

- Ensure the `PATCH_EVAL_SVC_CONFIG` env var is set.  You may remove the "example" suffix from `/src/patch-evaluation-service/.env.example` remove the "example suffix" and set the appvar contained within `PATCH_EVAL_SVC_CONFIG` to point to the above "config.json" and source the file into your environment to use

### Imminent updates
- update config.json
- take input from mqtt: this changes where we extract the json files holding the crash details
- take input from output of patching service: changes the path holding the patched codes
- create batched results csv (headers: executable name, # triggers addressed, # triggers failed to address, success %, success designation [S, P, F])
- testing suite
  

