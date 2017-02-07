Forge Release Process
=====================

Versioning
----------

* Follow the [Semantic Versioning][] guidelines.
* Use version X.Y.Z-dev in dev mode.
* Use version X.Y.Z for releases.

Master Branch Release Process
-----------------------------

* Ensure [tests pass](./README.md#testing).

## Update the main repository:

* Commit changes.
* Update the [CHANGELOG](./CHANGELOG.md) as needed using rougly
  [Keep a CHANGELOG][] style.
* `$EDITOR package.json`: update to release version and remove `-dev` suffix.
* `git commit package.json -m "Release {version}."`
* `git tag {version}`
* `$EDITOR package.json`: update to next version and add `-dev` suffix.
* `git commit package.json -m "Start {next-version}."`
* `git push`
* `git push --tags`

## Publish to NPM:

To ensure a clean upload, use a clean updated checkout, and run the following:

* `git checkout {version}`
* `npm install`
* `npm publish`

## Update bundled distribution

This is kept in a different repository to avoid the accumulated size when
adding per-release bundles.

* Checkout [forge-dist][].
* Build a clean Forge version you want to distribute:
  * `git checkout {version}`
  * `npm install`
  * `npm run build`
* Copy files to `forge-dist`:
  * `cp dist/forge.min.js{,.map} dist/prime.worker.min.js{,.map} FORGEDIST/dist/`
* Release `forge-dist`:
  * `git commit -a -m "Release {version}."`
  * `git tag {version}`
  * `git push`
  * `git push origin {version}`

Older Branch Release Process
----------------------------

In order to provide support for Bower (and similar) for current built bundle
releases and historical releases the [forge-dist][] repository needs to be
updated with code changes and tags from the main repository. Once a historical
branch, like 0.6.x, on the main repository is updated and tagged, do the
following:

* Checkout [forge-dist][].
* Setup an upstream branch:
  * `git remote add upstream git@github.com:digitalbazaar/forge.git`
  * `git fetch upstream`
* Merge changes:
  * `git checkout 0.6.x`
  * `git merge upstream/0.6.x`
* Push code and tag(s):
  * `git push`
  * `git push origin {version}`

[Keep a CHANGELOG]: http://keepachangelog.com/
[Semantic Versioning]: http://semver.org/
[forge-dist]: https://github.com/digitalbazaar/forge-dist
