set -ex
# SET THE FOLLOWING VARIABLES
# docker hub username
USERNAME=phucsnguyenv
# image name
IMAGE=connector-talosip
# ensure we're up to date
# bump version
# docker run --rm -v "$PWD":/app $USERNAME/bump patch
version=`cat VERSION`
echo "version: $version"
# run build
./build.sh
# tag it
docker tag $USERNAME/$IMAGE:$version $USERNAME/$IMAGE:latest 
# push it
docker push $USERNAME/$IMAGE:latest
docker push $USERNAME/$IMAGE:$version