set -ex
# SET THE FOLLOWING VARIABLES
# docker hub username
USERNAME=phucsnguyenv
# image name
IMAGE=connector-virustotal-reference
version=`cat VERSION`
# ensure we're up to date
# bump version
# docker run --rm -v "$PWD":/app $USERNAME/bump patch
echo "version: $version"
# run build
./build.sh
# tag it
docker tag $USERNAME/$IMAGE:latest $USERNAME/$IMAGE:$version
# push it
docker push $USERNAME/$IMAGE:latest
docker push $USERNAME/$IMAGE:$version