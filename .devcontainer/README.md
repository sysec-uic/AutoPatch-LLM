# Using bind mounts

By default the devcontainer will run as the "vscode" user.

The service will itself run under the "appuser" user that exists only inside the service's container.  

If you are running inside a devcontainer and want to run the service in docker compose you will need to make sure the filesystem permissions are setup correctly.  

By default you cannot run docker compose from inside the devcontainer and expect host filesystem bind mounts to "pass-through" the devcontainer.  If you are inside the devcontainer, then run the service using "python main.py" or using the bundled debugger debugpy by clicking on the Run and Debug iscon.  Outside of the devcontainer, you may run the service inside docker context by running "docker compose up" which should be considered a CLI shortcut to using "docker run [...]" where the docker-compose file is used to declare the service's runtime interface in source control and provide for environment variable injection.  To access the container's context interactively, run "docker compose run --rm autopatch bash" from where you can assume the same user that the service would use at runtime and you can observe the filesystem and environment context.

Running the service from inside a devcontainer with docker compose is not yet supported as support for pass-through filesystem permissions would need to be added first.  If you are inside the devcontainer, you should run the service via the CLI ("python main.py"), or the Run and Debug window inside vscode.
- If you want to add a feature to pass-through filesystem permissions to bind mount volumes from your host (where your username is "some-username" for example) you will need to align the linux filesystem permissions and commit an update, as we have not added that configuration to this project at the time of writing.

In this project docker compose is simply to aid interactive development and is not intended to be used as a deployment mechanism as there will k8s or similar to run the container in production environments.
