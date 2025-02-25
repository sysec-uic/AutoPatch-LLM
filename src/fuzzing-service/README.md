# Fuzzing Service

## How to Use

- use config.json when running as a container, like with docker-compose or k8s
- use dev-config.json when running interactively like in a debugger inside a devcontainer, or on your local host system

- Ensure the `FUZZ_SVC_CONFIG` env var is set.  You may remove the "example" suffix from `/src/fuzzing-service/.env.example` remove the "example suffix" and set the appvar contained within `FUZZ_SVC_CONFIG` to point to the above "config.json" and source the file into your environment to use

## Logging config

- if you like, set your logging to be less verbose in logging-config.json

- If you want to collect debut logs edit the logging-config.json file handler to point to a file that exists on host system if running locally, or mount a host volume to /app/logs/ inside the contianer to collect debug logs from /app/logs/debug.log
