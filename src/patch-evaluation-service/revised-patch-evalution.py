import os
import subprocess
import sys
from pathlib import Path

# 1) build the docker image within the local file system ( must pass one for the lack of confusion)


# Global File-name to build docker images with
# Naming convention:
# f everyword of the later is captil then it's global var
DockerFileName = "Dockerfile_Arvo_v1"
DockerFilePath = "~/AutoPatch-LLM/src/patch-evaluation-service/"


def locate_docker_file(filename=DockerFileName, filepath=DockerFilePath):
    # double check if the file path is relative and correct
    if filepath.startswith("~/AutoPatch-LLM/src/patch-evaluation-service/") != True:
        print(
            "Please make sure the file path is in ~/AutoPatch-LLM/src/patch-evaluation-service/"
        )

    current_working_dir = os.getcwd()
    filepath = os.path.abspath(filepath)
    filepath = filepath.split("~", 1)[0]

    print("***Logs=Evaluation Services=:The current working dir:")
    print(current_working_dir)
    if current_working_dir is filepath:
        print("the current working directory is not correct")
    # checking the current path to the docker file and the file name
    # don't change this, can be removed.
    # only change the global name first
    absolute_path = os.path.abspath(filename)
    print("***Logs=Evaluation Services=:The current Path For the dockerfile is:")
    print(absolute_path)
    if os.path.exists(absolute_path) != True:
        print("Logs=Evaluation Services=:Docker file location do not exits")
        print("Set the file path into ~/AutoPatch-LLM/src/patch-evaluation-service/")
        exit()


## Function:- Modify DockerFile
## this function should get some custom addtions that allows the user to build and create
# a new version of the docker image
def modify_dockerfile(filenmae=DockerFileName):
    # read the file name, and make some chagnes to it
    print("making changes to the file docker file")


## function:- Build DockerFile
## the follwing function should be running in Aysnc and show display
# also should display some detials about what's hapennaing
async def build_dockerfile(filenmae=DockerFileName):
    print("***Logs=Evaluation Services=: Build DockerFile")
    cmd = ["sudo", "docker", "build", "-f", filenmae, "-t", "docker_evalution", "."]
    result = subprocess.run(cmd, capture_output=True, text=True)
    print("STDOUT:\n", result.stdout)


## Function:- Run Dockerfile
#
#
def run_dockerfile(filenmae=DockerFileName):
    print("***Logs=Evaluation Services=: Run DockerFile")
    cmd = [
        "sudo",
        "docker",
        "build",
        "--no-cache",
        "-f",
        filenmae,
        "-t",
        "docker_evalution",
        ".",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    print("STDOUT:\n", result.stdout)


def main():
    ## makeing sure the docker file do exists
    print("************* Patch Evlaution Servies Utils *********************")
    locate_docker_file()
    build_dockerfile(DockerFileName)


main()
