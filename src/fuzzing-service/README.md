# Fuzzing Service

## How to Use in Dev

-  Remove the "example" suffix from `/src/fuzzing-service/config.json.example`
- Ensure the `FUZZ_SVC_CONFIG` env var is set.  You may remove the "example" suffix from `/src/fuzzing-service/.env.example` remove the "example suffix" and set the appvar contained within `FUZZ_SVC_CONFIG` to point to the above "config.json" and source the file into your environment to use 
