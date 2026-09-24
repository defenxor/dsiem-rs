# Docker image build files

From the repository root, run `./scripts/dockerbuild.sh defenxor/dsiem-rs wolfi`. The required second argument selects `wolfi`, `alpine`, `ubuntu`, or `alpine_musl`.

The helper prepares a build context and builds the intermediate images required by the final Dockerfile. See [building from source](../../../docs/building.md#docker-image) for tags, prerequisites, and build variables.
