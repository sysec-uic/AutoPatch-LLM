# AutoPatch Datatypes <!-- omit in toc -->
- [Building and Installing the module](#building-and-installing-the-module)
- [Using a datatype](#using-a-datatype)
- [Creating new datatypes](#creating-new-datatypes)


This package is to hold shared simple data classes for use by AutoPatch

> [!WARNING]  
> If you update a datatype be sure to rebuild and reinstall the module.  If you make breaking interface changes make sure you update the minor version number of the  module

## Building and Installing the module

First build the package
Navigate to `/workspace/AutoPatch-LLM/src/autopatchdatatypes`

Then run
```sh
python -m build

> [...]
> Successfully built autopatchdatatypes-0.2.0.tar.gz and autopatchdatatypes-0.2.0-py3-none-any.whl
```

Then while still inside the `/workspace/AutoPatch-LLM/src/autopatchdatatypes` directory install the package with:

NOTE: you may need to use the `--break-system-packages` CLI flag if you are running inside the dev container

```sh
pip install .

> [...]
> Successfully installed autopatchdatatypes-0.2.0
```

## Using a datatype

Then feel free to import the package and use the datatypes in your services like so:

```python
import base64
from autopatchdatatypes import CrashDetail

# Encode
crash_detail_string = 'hello world'
encoded_bytes = base64.b64encode(crash_detail_string.encode('utf-8'))
print("Encoded:", encoded_bytes)

>>> Encoded: b'aGVsbG8gd29ybGQ='

# Use datatype
crash_detail = CrashDetail("dummy_executable_name", crash_detail_string, False)

print(type(crash_detail))
print(crash_detail)

>>> <class 'autopatchdatatypes.crash_detail.CrashDetail'>
>>> CrashDetail(executable_name='dummy_executable_name', base64_message=b'aGVsbG8gd29ybGQ=', input_from_file=False)

# Decode
decoded_bytes = base64.b64decode(encoded_bytes)
decoded_string = decoded_bytes.decode('utf-8')
print("Decoded:", decoded_string)

>>> Decoded: hello world
```

## Creating new datatypes

Use the `@dataclass` decorator from the standard library, create new datatypes in their own files at `/workspace/AutoPatch-LLM/src/autopatchdatatypes/autopatchdatatypes/example_datatype.py`


```python
from dataclasses import dataclass


@dataclass
class ExampleDatatype:
    some_value: int
    some_other_value: str
```
