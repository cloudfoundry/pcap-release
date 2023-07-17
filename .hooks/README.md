# Git Hooks

Run conventional commit checks locally without any tool installation

## Usage

Adjust the git commit hook configuration as follows, from the root directory of pcap-release:

```shell
git config core.hooksPath .hooks
```

Please note that any hooks you had in other directories may not work.

Alternatively you can also soft-link the commit-msg script:

```shell
ln -s .hooks/commit-msg .git/hooks/commit-msg
```

This invocation will fail if you have a commit-msg hook already, in order to not break existing hooks.