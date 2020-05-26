set -ex
# SET THE FOLLOWING VARIABLES
# docker hub username
USERNAME=phucsnguyenv
# image name
IMAGE=connector-internal-import
docker build -t $USERNAME/$IMAGE:latest .