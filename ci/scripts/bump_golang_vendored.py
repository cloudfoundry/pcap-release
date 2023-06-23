#!/usr/bin/env python

import datetime
import os
import re
import subprocess
import sys
import textwrap
from github import Github, GithubException, UnknownObjectException
from git import Repo, GitCommandError
import yaml
from ruamel.yaml import YAML

# Required env vars
GH_TOKEN = os.environ["GITHUB_COM_TOKEN"]
PR_BASE = os.environ["PR_BASE"]
PR_ORG = os.environ["PR_ORG"]
PR_LABEL = os.environ["PR_LABEL"]
GO_PACKAGE_REPO_ROOT = os.environ["GO_PACKAGE_REPO_ROOT"]
GIT_AUTHOR_NAME = os.environ["GIT_AUTHOR_NAME"]
GIT_AUTHOR_EMAIL = os.environ["GIT_AUTHOR_EMAIL"]

GCP_SERVICE_KEY = os.environ["GCP_SERVICE_KEY"]

# Github.com
GH = Github(GH_TOKEN)

# Current Git Repository (pcap-release)
ORIGIN_PATH = f"{PR_ORG}/pcap-release"
REMOTE_REPO = GH.get_repo(ORIGIN_PATH)
LOCAL_REPO = Repo(os.curdir)
LOCAL_GIT = LOCAL_REPO.git

with LOCAL_REPO.config_writer() as config:
    config.add_section("user")
    config.set("user", "name", GIT_AUTHOR_NAME)
    config.set("user", "email", GIT_AUTHOR_EMAIL)

    gh_url = f"url \"https://{GH_TOKEN}@github.com/\""
    config.add_section(gh_url)
    config.set(gh_url, "insteadOf", "https://github.com/")

# golang-release repo (github.com & local path)
GOLANG_RELEASE_REPO = GH.get_repo("bosh-packages/golang-release")
GOLANG_RELEASE_REPO_LOCAL = Repo(GO_PACKAGE_REPO_ROOT)

# Paths in this Repository
PRIVATE_YAML_PATH = "config/private.yml"
PACKAGE_NAME = "golang-1-linux"
PACKAGE_PATH = f"packages/{PACKAGE_NAME}"
VERSION_PATH = PACKAGE_PATH + "/version"
DOCS_VERSION_PATH = "docs/go.version"
VENDORED_COMMIT_PATH = PACKAGE_PATH + "/vendored-commit"
SPEC_LOCK_PATH = PACKAGE_PATH + "/spec.lock"
GOLANG_RELEASE_INDEX_YML_PATH = f".final_builds/{PACKAGE_PATH}/index.yml"

# Bump Branch Name
PR_BRANCH = "golang-auto-bump"
BRANCH_FULLNAME = f"{PR_ORG}:{PR_BRANCH}"


def main():
    # get the latest version via PyGithub (without cloning repository) for performance/traffic reasons
    latest_version = get_latest_version()

    # if re.match(r"^\d+\.\d+$", latest_version):
    #     print(f"Skipping unpatched version {latest_version}.")
    #
    #     sys.exit(0)

    current_version = get_current_version()

    if latest_version != current_version:
        print(f"A new version exists: {current_version} --> {latest_version}")
        if open_pr_exists(REMOTE_REPO):
            print("A PR for a go version bump already exists. Exiting.")
        else:
            # Setup private.yml with Blobstore Credentials (for 'bosh vendor-package' later)
            write_private_yaml()

            try:
                check_for_conflicting_bump_branch(REMOTE_REPO)
            except Exception:
                print("An golang-bump PR exists, skipping. Merge or delete the other branch to bump dependencies.")
                return
            
            print("No open golang-bump PR exists, bump required.")
            test_local_golang_release_clone(latest_version)
            blob_link = run_vendor_package()

            checkout_bump_branch()
            update_versioning_files(latest_version)
            create_pr(current_version, latest_version, blob_link)

    else:
        print(f"Already on latest version {current_version}, exiting.")


def get_current_version():
    with open(VERSION_PATH, "r") as version_file:
        return version_file.read()


def get_latest_version():
    version_file = GOLANG_RELEASE_REPO.get_contents(VERSION_PATH)
    return version_file.decoded_content.decode()


def test_local_golang_release_clone(latest_version_remote):
    # get actual latest version from local repository, compare against remote
    golang_release_version_file_path = os.path.join(GO_PACKAGE_REPO_ROOT, VERSION_PATH)
    with open(golang_release_version_file_path, "r") as file:
        latest_version_local = file.read()
    if latest_version_remote != latest_version_local:  # these should never differ, unless there was an error in cloning golang-release
        raise Exception(
            f"golang_release versions differ between github.com remote ({latest_version_remote}) and local clone in {GO_PACKAGE_REPO_ROOT} ({latest_version_local})"
        )


def run_vendor_package():
    # Documentation for bosh vendor-package: https://bosh.io/docs/package-vendoring/#vendor
    cmd_params = ["bosh", "vendor-package", PACKAGE_NAME, GO_PACKAGE_REPO_ROOT]
    print(f"Running '{' '.join(cmd_params)}' ...")

    # run as subprocess and handle errors
    process = subprocess.Popen(cmd_params, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if stdout:
        # we don't expect any stdout under normal behaviour, might be useful for debugging though
        print(stdout.decode("utf-8"), file=sys.stdout)
    response = stderr.decode("utf-8")  # bosh vendor-package writes success info to stderr for some reason
    print(response, file=sys.stdout)
    if process.returncode != 0:
        raise Exception(f"bosh vendor-package failed. Aborting: {response}")

    if response == "":
        print("bosh vendor-package succeeded but provided no output. "
              "The golang-package-blob for this version has been uploaded previously. Continuing.")
    # extract blobstore URL
    rgx = r".*? Successfully uploaded file to (.*?)$"
    match = re.match(rgx, response)
    if match:
        groups = match.groups()
        if groups and len(groups) == 1:
            blob_link = groups[0]
            print(f"bosh vendor-package successful. Link to new blob: {blob_link}")
            return blob_link

    print("No new blob was uploaded. See messages above.")


def open_pr_exists(repo) -> bool:
    prs_exist = False
    for pr in repo.get_pulls(
            state="open", base="master", head=BRANCH_FULLNAME
    ):  # theoretically there should never be more than one open PR, print them anyway
        print(f"{repo.name}: Open {PR_BRANCH} PR: {pr.html_url}")
        prs_exist = True

        # print statement for Jenkins Job build description
        pr_version = pr.title.split(" ")[-1]
        print(f"PR_URL={pr.html_url} VERSION={pr_version} ACTION=ALREADY_EXISTS")
    return prs_exist


def check_for_conflicting_bump_branch(repo):
    # the bump branch should not exist after a successful previous run/merge. If there is an existing branch,
    # we risk including other changes in PR, so we abort instead.
    # We're checking on the remote repo since we just cloned it and don't expect any local changes yet.
    try:
        repo.get_branch(PR_BRANCH)
        raise Exception(
            f"{repo.name}: The branch {PR_BRANCH} already exists in the remote repository. It might be a stale branch. Aborting.")
    except GithubException:
        print(f"No conflicting {PR_BRANCH} branch exists on remote repository. Continuing.")


def update_versioning_files(latest_version):
    # write current golang-release commit hash to vendored-commit file
    repo = Repo(GO_PACKAGE_REPO_ROOT)
    current_sha = repo.head.object.hexsha
    with open(VENDORED_COMMIT_PATH, "w") as vendored_commit_file:
        vendored_commit_file.write(current_sha)

    # set versions file
    with open(VERSION_PATH, "w") as version_file:
        version_file.write(latest_version)

    with open(DOCS_VERSION_PATH, "w") as docs_version_file:
        modified_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        docs_version_file.write(f"This file was updated by CI on {modified_time}\n")
        docs_version_file.write(f"go{latest_version}")


def write_private_yaml():
    private_yml = {
        "blobstore": {
            "options": {
                "credentials_source": "static",
                "json_key": GCP_SERVICE_KEY,
            }
        }
    }

    with open(PRIVATE_YAML_PATH, "w") as file:
        yaml.dump(private_yml, file, default_flow_style=False)


def checkout_bump_branch():
    print(f"Checking out branch {PR_BRANCH}")
    try:
        LOCAL_GIT.checkout("-b", PR_BRANCH)
    except GitCommandError as exception:
        print(f"Encountered exception while checking out {PR_BRANCH}: {exception}")


def create_pr(current_version, new_version, blob_link):
    # create commit
    print("Creating git commit...")
    # add changed files
    LOCAL_GIT.add(GOLANG_RELEASE_INDEX_YML_PATH, "-f")
    LOCAL_GIT.add(VERSION_PATH)
    LOCAL_GIT.add(DOCS_VERSION_PATH)
    LOCAL_GIT.add(VENDORED_COMMIT_PATH)
    LOCAL_GIT.add(SPEC_LOCK_PATH)
    # create and push commit
    LOCAL_GIT.commit("-m", f"dep(go): bump golang to {new_version}")
    LOCAL_GIT.push("origin", PR_BRANCH)

    # create PR
    print("Creating pull request...")
    pr_body = textwrap.dedent(
        f"""
        Automatic bump of golang-1-release from go version {current_version} to version {new_version}.

        Link to golang blobstore package: {blob_link}

        After merge, consider making a new release.
    """
    )
    pr = REMOTE_REPO.create_pull(
        title=f"dep(go): Bump golang version to {new_version}",
        body=pr_body,
        base=PR_BASE,
        head=BRANCH_FULLNAME,
    )

    pr.add_to_labels(PR_LABEL)


def update_git_content(file_path, file_content, latest_version):
    # latest_version may contain a patch version which we need to strip
    latest_major_minor = ".".join(latest_version.split(".")[0:2])

    if file_path == "go.mod":
        new_file_content = re.sub(r"^(go [0-9](.[0-9]+)+)$", "go " + latest_major_minor, file_content, 1, re.MULTILINE)
    elif file_path == "Jenkinsfile":
        # Should consider if we always have sometimes version with only major.minor pattern (no patch).
        new_file_content = re.sub(r"go 'Go [0-9](.[0-9]+)+'", "go 'Go " + latest_major_minor + "'", file_content)
    elif file_path == ".github/workflows/golint.yml":
        # Regex substitution for version number in Yaml File, e.g.
        # env:
        #   GOLANG_VERSION: 1.20
        regex_pattern = r"^(env:\n\s+GOLANG_VERSION: )\d+(.\d+)+$"
        new_file_content = re.sub(regex_pattern, rf"\g<1>{latest_version}", file_content, 1, re.MULTILINE)
    else:
        print("This filename is not in the list of to be processed files.")
        return file_content
    return new_file_content


def cleanup():
    # make sure no credentials remain
    try:
        os.remove(PRIVATE_YAML_PATH)
    except Exception as e:
        print(f"Could not clean up: {e}")


if __name__ == "__main__":
    try:
        main()
    finally:
        cleanup()
