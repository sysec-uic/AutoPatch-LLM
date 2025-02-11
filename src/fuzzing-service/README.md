# Fuzzing Service

## How to Use in Dev

-  Remove the "example" suffix from `/src/fuzzing-service/config.json.example`
- Ensure the `FUZZ_SVC_CONFIG` env var is set.  You may remove the "example" suffix from `/src/fuzzing-service/.env.example` remove the "example suffix" and set the appvar contained within `FUZZ_SVC_CONFIG` to point to the above "config.json" and source the file into your environment to use 

## How to use in Prod (SECTION WIP)

- Set `FUZZ_SVC_CONFIG` to `/app/config/config.json`
- Mount `/src/fuzzing-service/config.json` to `/app/config/config.json`
- Mount `/src/fuzzing-service/logging-config.json` to `/app/config/logging-config.json`
- If using optional file logging handler.  In `logging-config.json` set "handlers.file_debug_handler.filename" to `/app/logs/autopatch.fuzzing-service.debug.log`
- Configure Cloud Logging as appropriate