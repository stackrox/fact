# Managing a `fact` release

## Create the release branch

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

At this point you will need to wait for the downstream release engineers
to create the git resources for Konflux before proceeding.

## Update Konflux resources and application version

1.  Set the following environment variables:

    *   `STACKROX_SUFFIX`: The major and minor versions of ACS that will use this `fact` version (e.g., `4-10`).
    *   `FACT_RELEASE`: The release version you set in the previous section.
    *   `FACT_PATCH`: The patch version for this release (e.g., `0`).

    ```sh
    export STACKROX_SUFFIX=4-10
    export FACT_RELEASE=0.2
    export FACT_PATCH=0
    ```

1.  On the release branch, run the following commands to update the
Konflux build configuration and the application version.

    ```sh
    sed -i \
        -e "/appstudio.openshift.io\/application: / s/$/-${STACKROX_SUFFIX}/" \
        -e "/appstudio.openshift.io\/component: / s/$/-${STACKROX_SUFFIX}/" \
        -e "/serviceAccountName: / s/$/-${STACKROX_SUFFIX}/" \
        .tekton/fact-build.yaml

    sed -i \
        -e "/^version = / s/\".*\"/\"${FACT_RELEASE}.0\"/" \
        fact/Cargo.toml
    ```

1. Create a new branch for these changes and push it to the repository.
    ```sh
    git checkout -b "release/konflux-resources-${FACT_RELEASE}"
    git add .
    git commit -m "Update Konflux resources for release ${FACT_RELEASE}"
    git push --set-upstream origin "release/konflux-resources-${FACT_RELEASE}"
    ```

1. Create a PR pointing to the release branch and get it merged.
1. Once the PR is in, you can go ahead and tag the fact release.

    ```sh
    git checkout "release-${FACT_RELEASE}"
    git pull --ff-only
    git tag "${FACT_RELEASE}.0"
    git push origin "${FACT_RELEASE}.0"
    ```

1. Ensure the Konflux and GitHub Actions builds succeed and the
corresponding container images are pushed.

## Handling path releases

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
