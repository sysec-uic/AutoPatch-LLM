# Setup FuzzBench on Ubuntu 22.04 LTS

This guide explains how to set up and run [Google FuzzBench](https://google.github.io/fuzzbench/getting-started/prerequisites/) on `Ubuntu 22.04 LTS`. These instructions have been tested on `Ubuntu 22.04 LTS`.

## 1. Set Up Docker and Essential Tools
### a. Update Package Index and Install Docker
Run the following commands to update your package list and install `Docker` (along with `oh-my-zsh`, if desired):

```
sudo apt-get update -y
git clone https://github.com/sysec-uic/.setup.sh.git
cd .setup.sh
./setup.sh -h       # Show help
./setup.sh -oD      # Install oh-my-zsh and docker
```
Re-login the shell to activate `oh-my-zsh`, and unprivileged `docker` environment.

### b. Install Build Essentials and Python Development Packages
Install the necessary build tools and Python development libraries:
```
sudo apt-get install -y build-essential
sudo apt-get install -y python3.10-dev python3.10-venv
```

## 2. Configure Core Dumps if Running FuzzBench on Google Cloud VM

If you are running on a Google Cloud VM, you might need to reset the core dump naming pattern. This helps ensure that core dump files are generated correctly when a program crashes:
```
sudo sh -c "echo core >/proc/sys/kernel/core_pattern"
```

## 3. Clone FuzzBench and Install Dependencies
Clone the `FuzzBench` repository and install its dependencies:
```
git clone https://github.com/google/fuzzbench
cd fuzzbench
make install-dependencies
```
Activate the provided Python virtual environment and run a presubmit check to verify your setup:
```
source .venv/bin/activate
make presubmit
```

Create a configuration file named `exp.yaml` with the following content. This file defines parameters for your fuzzing experiment:
```
# The number of trials of a fuzzer-benchmark pair.
trials: 5

# The amount of time in seconds that each trial is run for.
# 1 day = 24 * 60 * 60 = 86400
max_total_time: 86400

# The location of the docker registry.
# FIXME: Support custom docker registry.
# See https://github.com/google/fuzzbench/issues/777
docker_registry: gcr.io/fuzzbench

# The local experiment folder that will store most of the experiment data.
# Please use an absolute path.
experiment_filestore: /tmp/experiment-data

# The local report folder where HTML reports and summary data will be stored.
# Please use an absolute path.
report_filestore: /tmp/report-data

# Flag that indicates this is a local experiment.
local_experiment: true
```
**Note**: Ensure you use absolute paths for both **experiment_filestore** and **report_filestore**.

## 4. Execute the fuzzer(s):
Define an environment variable for your experiment name:
```
export EXPERIMENT_NAME=myexp
```
Execute the experiment using the provided configuration, selecting the benchmarks and specifying AFL as the fuzzer:
```
PYTHONPATH=. python3 experiment/run_experiment.py \
--experiment-config exp.yaml \
--benchmarks bloaty_fuzz_target_52948c harfbuzz_hb-shape-fuzzer_17863b libxml2_xml_e85b9b mbedtls_fuzz_dtlsclient_7c6b0e mruby_mruby_fuzzer_8c8bbd php_php-fuzz-parser_0dbedb  \
--experiment-name $EXPERIMENT_NAME \
--fuzzers afl
```
Once the experiment completes, an HTML report is generated. Open the report in your web browser:
```
/tmp/report-data/$EXPERIMENT_NAME/index.html
```

To search for potential crashes in your experiment data, use `grep` to find lines indicating unique crashes:
```
grep "1 uniq crashes found" /tmp/experiment-data/* -rn
```
Or view all instances with:
```
grep "uniq crashes found" /tmp/experiment-data/* -rn | less
```

**Note**: AFL got two applications (`bloaty_fuzz_target_52948c` and `harfbuzz_hb-shape-fuzzer_17863b`) with crashes running in 24 hours:
```
... ...
/tmp/experiment-data/myexp/experiment-folders/bloaty_fuzz_target_52948c-afl/trial-5/results/fuzzer-log.txt:640:[*] Fuzzing test
 case #14 (1417 total, 1 uniq crashes found)...
... ...
/tmp/experiment-data/myexp/experiment-folders/harfbuzz_hb-shape-fuzzer_17863b-afl/trial-6/results/fuzzer-log.txt:2379:[*] Fuzzi
ng test case #2437 (6086 total, 23 uniq crashes found)...
```

Happy fuzzing!