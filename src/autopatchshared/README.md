# Section: Shared Utilities

## What Problem Do Shared Utilities Solve?

Imagine several of our services need to:
1. Start logging messages in a consistent format.
2. Get the current time in a standard way for records.
3. Run a `make compile` command to build C code.
4. Load their configuration from a JSON file

If each service implemented these functions independently, we'd have a lot of duplicated code. This is bad because:
* **It's more work:** You write the same logic multiple times.
* **It's error-prone:** If you find a bug in one implementation, you have to remember to fix it everywhere else.
* **It's inconsistent:** Slight differences in implementation could lead to unexpected behavior.

This follows a core programming principle: **DRY (Don't Repeat Yourself)**.

**Use Case:** The Fuzzing Service needs to compile code using `make` before fuzzing. The Patch Evaluation Service also needs to compile the patched code to test it. Instead of both services having their own separate code to run `make`, they can both use a single, shared function from the utilities toolbox.

The Shared Utilities module (`autopatchshared`) provides this common toolbox, containing reliable, reusable functions for tasks needed by multiple services.

## The Tools in Our Shared Toolbox

The `autopatchshared` library contains several useful functions. Let's look at the main ones:

1. **`init_logging(logging_config_path, appname)`:**
  * **What it does:** Sets up the logging system for a service. It reads logging settings (like format, log level, where to log) from a specified JSON configuration file. This ensures all services log messages in a consistent way.
  * **Analogy:** This is like handing out the official company notepad and pen, ensuring everyone takes notes in the standard format.

2. **`load_config_as_json(config_path, logger)`:**
  * **What it does:** It reads a JSON configuration file and returns the settings as a Python dictionary.
  * **Analogy:** This is the standard procedure for reading the instruction sheet for any specific task.

3. **`get_current_timestamp()`:**
  * **What it does:** Returns the current date and time as a string, formatted in a standard way (ISO 8601 UTC format, like `2023-10-27T10:30:00Z`). This is useful for timestamps in logs or records.
  * **Analogy:** This is like a perfectly synchronized clock available to everyone, ensuring all timestamps are consistent.

## How to Use the Shared Utilities

Services can easily import and use these functions from the `autopatchshared` library.

**Example: Getting a Timestamp**

Anywhere a service needs a timestamp, it can just call `get_current_timestamp`.

```python
from autopatchshared import get_current_timestamp

# Get the current time in standard format
now_iso = get_current_timestamp()

print(f"Processing started at: {now_iso}")
# Output might look like: Processing started at: 2024-03-15T14:22:05Z
```
This is very simple – just call the function and get a consistently formatted timestamp string.

## Conclusion: Putting It All Together

In section we looked at about the **Shared Utilities** (`autopatchshared`) - our common toolbox. By centralizing functions for tasks like logging (`init_logging`), getting timestamps (`get_current_timestamp`), we avoid code duplication, improve consistency, and make the whole system easier to maintain.

Each component of AutoPatch plays a vital role, working together asynchronously through the message broker to automatically find, analyze, patch, and evaluate vulnerabilities in C code.
