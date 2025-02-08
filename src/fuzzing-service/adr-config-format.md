# Fuzzing Service Configuration Format Architectureal Design Record

JSON vs YAML

Parsing in YAML easily would point to using a third part library like PyYaml, unfortunately there is no LICENSE in their repository.

Parsing in JSON is supported by the standard library using `dataclasses`.  So we will use JSON configuration format unless there is another development in the YAML space allowing us to support both JSON and YAML simultaneously.
