# How to contribute

This is a community-driven project and we happily accept contributions from anyone interested in helping. To keep things well-organized and flowing smoothly, here are a few guidelines.

## Getting Started

To get started setup a virutal environment using `virtualenv venv` followed by `source venv/bin/activate` to give yourself a clean Python environment. You can install development libraries using `pip install -r requirements-dev.txt`.

threat_note uses [Yelp's Pre-Commit](http://pre-commit.com/) to ensure consistency and following good practices. If you installed libraries using the `requirements-dev.txt` you'll can run `pre-commit install` before you start submitting code. Check your code using `pre-commit run --all-files` (as well as whenever you commit).

## GitHub

You need a [GitHub](https://github.com) account for most everything like opening or commenting on issues, or submitting code patches (the GitHub parlance here is "pull request").

## Bug reporting

Yes, we have some bugs. Some of them we know about (and are working on), others we need somebody to tell us about. If you submit a bug report (issue), please be sure to include the actual program output and let us know anything relevant about the environment (OS and Python version, for example, or if you have made any changes to the code).

## Pull requests

The easiest and best way to do this is to [fork our repository](https://help.github.com/articles/fork-a-repo) and then [send a pull request](https://help.github.com/articles/using-pull-requests). In your description, please be sure to note any related issues (for example, if your PR fixes a previously-reported bug or implements an existing enhancement request).

We will review and possibly request additional changes before merging. The best patches will be those that conform to [PEP8](http://legacy.python.org/dev/peps/pep-0008/) and refrain from introducing new dependencies as much as possible. Sometimes that will be okay, of course, if it does something new and awesome! Also please keep in mind that Utility Belt is released under the [MIT license](LICENSE) and this will include all code sent back to us.

__Note:__ _This CONTRIBUTING.md was shamelessly ripped off of [technoskald's](https://github.com/technoskald) epic [Maltrieve project](https://github.com/technoskald/maltrieve)._
