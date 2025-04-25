# assets/remove-all-docker-images.sh
# this script is used to remove all docker images from the local machine
# and is not strictly a component of the application but rather a utility
# script to clean up the local docker environment
#
docker rmi -f $(docker images -q)
