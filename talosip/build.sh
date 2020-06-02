set -ex
# SET THE FOLLOWING VARIABLES
# docker hub username
USERNAME=phucsnguyenv
# image name
IMAGE=connector-talosip
version=`cat VERSION`
docker build -t $USERNAME/$IMAGE:$version .