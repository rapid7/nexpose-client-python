# Contributing to nexpose-client-python

The users and maintainers of nexpose-client-python would greatly appreciate any contributions
you can make to the project. These contributions typically come in the form of
filed bugs/issues or pull requests (PRs). These contributions routinely result
in new versions of the [nexpose-client-python library](https://pypi.python.org/pypi/nexpose) and the
[nexpose-client-python release](https://github.com/rapid7/nexpose-client-python/releases) to be released. The
process for each is outlined below.

## Contributing Issues / Bug Reports

If you encounter any bugs or problems with nexpose-client-python, please file them
[here](https://github.com/rapid7/nexpose-client-python/issues/new), providing as much detail as
possible. If the bug is straight-forward enough and you understand the fix for
the bug well enough, you may take the simpler, less-paperwork route and simply
file a PR with the fix and the necessary details.

## Contributing Code

nexpose-client-python uses a model nearly identical to that of
[Metasploit](https://github.com/rapid7/metasploit-framework) as outlined
[here](https://github.com/rapid7/metasploit-framework/wiki/Setting-Up-a-Metasploit-Development-Environment),
at least from a ```git``` perspective. If you've been through that process
(or, even better, you've been through it many times with many people), you can
do exactly what you did for Metasploit but with nexpose-client-python and ignore the rest of
this document.

On the other hand, if you haven't, read on!

### Fork and Clone

Generally, this should only need to be done once, or if you need to start over.

1. Fork nexpose-client: Visit https://github.com/rapid7/nexpose-client-python and click Fork,
   selecting your github account if prompted
2. Clone ```git@github.com:<your-github-username>/nexpose-client-python.git```, replacing
```<your-github-username>``` with, you guessed it, your Github username.
3. Add the master nexpose-client-python repository as your upstream:
```
git remote add upstream git://github.com/rapid7/nexpose-client-python.git
git fetch --all
```

### Branch and Improve

If you have a contribution to make, first create a branch to contain your
work. The name is yours to choose, however generally it should roughly
describe what you are doing. In this example, and from here on out, the
branch will be wow, but you should change this.

```
git fetch --all
git checkout master
git rebase upstream/master
git checkout -b wow
```

Now, make your changes, committing as necessary, using useful commit messages:

```
vim CONTRIBUTING.md
git add CONTRIBUTING.md
git commit -m "Adds a document on how to contribute to nexpose-client-python." -a
```

Please note that changes to [version.py](version.py) in PRs are almost never necessary.

Now push your changes to your fork:

```
git push origin wow
```

Finally, submit the PR. Navigate to ```https://github.com/<your-github-username>/nexpose-client-python/compare/wow```, fill in the details, and submit.

## Releasing New Versions

Typically this process is reserved for contributors with push permissions to
nexpose-client-python:

Be sure to regenerate the README.rst file if the README.md has changed. Use `pandoc -s -r markdown -w rst README.md -o README.rst` and validate the link URLs.

### Pypi Release

Pypi releases, for use with the `pip` command, are performed by a Jenkins job. Currently Jenkins access is restricted to Rapid7 employees. The package will be published at [https://pypi.python.org/pypi/nexpose](https://pypi.python.org/pypi/nexpose).

### Github Release

Some users may prefer to consume nexpose-client-python in a manner other than using git itself. For that reason, Github offers [Releases](https://github.com/blog/1547-release-your-software). Whenever a new version of the software is to be released, be kind and also create a new [Release](https://github.com/rapid7/nexpose-client-python/releases), using a versioning scheme identical to that used for the library.
