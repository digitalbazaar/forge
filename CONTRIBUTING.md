Contributing to forge
=====================

Want to contribute to forge? Great! Here are a few notes:

Code
----

* In general, follow a common [Node.js Style Guide][].
* Use version X.Y.Z-dev in dev mode.
* Use version X.Y.Z for releases.
* Ensure [tests pass](./README.md#testing).
* Read the [contributing](./README.md#contributing) notes.

Versioning
----------

* Follow the [Semantic Versioning][] guidelines.

Release Process
---------------

## Update the main repository:

* Commit changes.
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
* `npm publish`

## Update bundled distribution

This is kept in a different repository due to accumulated per-release bundle
sizes.

* Checkout [forge-dist][].
* Build a clean Forge version you want to distribute:
  * `git checkout {version}`
  * `npm run build`
* Copy files to `forge-dist`:
  * `cp dist/forge.min.js dist/prime.worker.min.js FORGEDIST/dist/`
* Release `forge-dist`:
  * Commit changes.
  * `git tag {version}`
  * `git push`
  * `git push --tags`

[Node.js Style Guide]: http://nodeguide.com/style.html
[README]: ./README.md
[Semantic Versioning]: http://semver.org/
[forge-dist]: https://github.com/digitalbazaar/forge-dist
[jshint]: http://www.jshint.com/install/
