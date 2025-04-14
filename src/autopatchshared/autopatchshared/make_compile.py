import logging
import subprocess


def make_compile(
    project_directory_full_path: str,
    output_executable_fully_qualified_path: str,
    compiler_tool_full_path: str,
    make_tool_full_path: str,
    logger: logging.Logger,
) -> bool:

    compile_command = f"{make_tool_full_path} -C {project_directory_full_path} compile "
    compile_command += f"CC_PATH={compiler_tool_full_path} "
    compile_command += f"EXEC_PATH={output_executable_fully_qualified_path}"

    with subprocess.Popen(
        compile_command,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        universal_newlines=True,
        shell=True,
    ) as compile_process:
        try:
            stdout, stderr = compile_process.communicate(timeout=10)
        except subprocess.TimeoutExpired as e:
            compile_process.kill()
            stdout, stderr = compile_process.communicate()
            logger.error(f"Compilation failed with {e}")
            return False
        if compile_process.returncode != 0:
            logger.error(
                f"Compilation failed with return code {compile_process.returncode}"
            )
            logger.error(f"stderr {stderr}")
            logger.error(f"stdout {stdout}")
            return False
        return True
