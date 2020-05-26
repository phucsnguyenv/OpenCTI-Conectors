set -ex
# SET THE FOLLOWING VARIABLES
# docker hub username
USERNAME=phucsnguyenv
# image name
IMAGE=connector-internal-import
version=`cat VERSION`
# ensure we're up to date
git pull
# bump version
# docker run --rm -v "$PWD":/app $USERNAME/bump patch
echo "version: $version"
# run build
./build.sh
# tag it
git add -A
git commit -m "version $version"
git tag -a "$version" -m "version $version"
git push
git push --tags
docker tag $USERNAME/$IMAGE:latest $USERNAME/$IMAGE:$version
# push it
docker push $USERNAME/$IMAGE:latest
docker push $USERNAME/$IMAGE:$version