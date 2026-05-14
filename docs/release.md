# Managing a `fact` release

## Automated release

There are two GHA workflows available to prepare a new release stream
and properly releasing a new version, they are aptly named:
- Prepare Release Branch
- Release New Version

When a release cycle is coming to an end and a new X.Y stream is needed,
running the `Prepare Release Branch` will do all the heavy lifting,
creating the new `release-X.Y` branch, a new internal `X.Y.x` tag and
opening PRs for updating the cargo toml and lock files, pinning Rust
version to use and updating the CHANGELOG.

Once a release engineer signals a new tag for fact is needed, the
`Release New Version` workflow can be used to push this tag
automatically. It will work for both the initial version of a new X.Y
stream, as well as for any future patch releases needed for that same
stream.

## Manual release

**Note**: This is a fallback method, only intended to be used if the
automated method fails for some reason. Stick to the automated method
whenever possible
---

### Create the release branch

1. Navigate to your local `stackrox/fact` git repository and ensure your
`main` branch is up to date.

    ```sh
    git checkout main
    git pull
    ```

1. Set the release environment variable.

    ```sh
    export FACT_RELEASE=0.2
    ```

1. Create an internal tag on the `main` branch to mark the point from
which the release is forked.

    ```sh
    git tag "${FACT_RELEASE}.x"
    git push origin "${FACT_RELEASE}.x"
    ```

1. Create and push the release branch.

    ```sh
    git checkout -b "release-${FACT_RELEASE}"
    git push --set-upstream origin "release-${FACT_RELEASE}"
    ```

### Update CHANGELOG.md and version on main

1.  Set the following environment variable:

    *   `FACT_RELEASE`: The next version of fact to be released.
    *   `FACT_DEV`: The version of fact that will enter the dev phase.

    ```sh
    export FACT_RELEASE=0.2
    export FACT_DEV=0.3
    ```

1.  On the `main` branch, run the following commands.

    ```sh
    sed -i \
        -e "s/^## Next/&\n\n## ${FACT_RELEASE}.0/" \
        CHANGELOG.md

    sed -i \
        -e "/^version = / s/\".*\"/\"${FACT_DEV}.0-dev\"/" \
        fact/Cargo.toml
    cargo update -p fact
    ```

1. Create a new branch for these changes and push it to the repository.
    ```sh
    git checkout -b "release/update-versions-${FACT_RELEASE}"
    git add .
    git commit -m "chore: update change log and application version for ${FACT_RELEASE}"
    git push --set-upstream origin "release/update-versions-${FACT_RELEASE}"
    ```

1. Create a PR pointing to the main branch and get it merged.

### Pin compiler version and update the application version

1.  Set the following environment variables:

    *   `FACT_RELEASE`: The release version you set in the previous
        section.
    *   `FACT_PATCH`: The patch version for this release (e.g., `0`).
    *   `RUST_VERSION`: The version of the rust compiler that will be
        used with this release, usually the latest stable rust version.
        (e.g., `1.88`).

    ```sh
    export FACT_RELEASE=0.2
    export FACT_PATCH=0
    export RUST_VERSION=1.88
    ```

1.  On the release branch, run the following commands.

    ```sh
    sed -i -e "s/^RUST_VERSION .*/RUST_VERSION ?= ${RUST_VERSION}/" \
        constants.mk

    sed -i \
        -e "/^version = / s/\".*\"/\"${FACT_RELEASE}.0\"/" \
        fact/Cargo.toml
    cargo update -p fact
    ```

1. Create a new branch for these changes and push it to the repository.
    ```sh
    git checkout -b "release/prepare-${FACT_RELEASE}"
    git add .
    git commit -m "chore: prepare release branch for ${FACT_RELEASE}"
    git push --set-upstream origin "release/prepare-${FACT_RELEASE}"
    ```

1. Create a PR pointing to the release branch and get it merged.

1. Since the release of artifacts via Konflux require some additional
configuration, you will need to wait for the release engineer to make
these and request a tag for fact. Once this happens, you can create a
new tag with the following commands:
    ```sh
    git checkout "release-${FACT_RELEASE}"
    git pull --ff-only
    git tag "${FACT_RELEASE}.0"
    git push origin "${FACT_RELEASE}.0"
    ```

1. Ensure the Konflux and GitHub Actions builds succeed and the
corresponding container images are pushed.

### Handling patch releases

1. Merge any backport PRs you need into the desired release branch.
1. Figure out the patch version to be released.
1. Change to the release branch, pull the latest version, tag it and
push

    ```sh
    export FACT_RELEASE=0.2
    export FACT_PATCH=1
    git checkout "release-${FACT_RELEASE}"
    git pull --ff-only
    git tag "${FACT_RELEASE}.${FACT_PATCH}"
    git push origin "${FACT_RELEASE}.${FACT_PATCH}"
    ```

1. Ensure the Konflux and GitHub Actions builds succeed and the
corresponding container images are pushed.
