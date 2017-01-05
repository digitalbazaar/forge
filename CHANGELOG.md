Forge ChangeLog
===============

## 0.7.0 - 2017-??-??

### Fixed

- Fix test looping bugs so all tests are run.

### Changed

- Major refactor to CommonJS plus a browser build system.
- Updated tests, examples, docs.
- Updated dependencies.
- Updated flash build system.
- Improve OID mapping code.
- Change test servers from Python to JavaScript.
- Improve PhantomJS support.
- Move Bower/bundle support to
  [forge-dist](https://github.com/digitalbazaar/forge-dist).

### Added

- webpack bundler support via `npm run build`:
  - Builds .js, .min.js, and sourcemaps.
  - Basic build: forge.js.
  - Build with extra utils and networking support: forge.all.js.
  - Builds extra support: jsbn.js.
- Browserify support in package.json.
- Karma browser testing.
- `forge.options` field.
- `forge.options.usePureJavaScript` flag.
- `forge.util.isNodejs` flag (used to select "native" APIs).
- Run PhantomJS tests in Travis-CI.
- Add "Donations" section to README.
- Add IRC to "Contact" section of README.
- Add "Security Considerations" section to README.
- Add pbkdf2 usePureJavaScript test.
- Add async rsa.generateKeyPair tests.

### Removed

- Can no longer call `forge({...})` to create new instances.
- Remove a large amount of old cruft.

### Notes

- This major update requires updating the version to 0.7.x. The existing
  work-in-progress "0.7.x" branch will be painfully rebased on top of this new
  0.7.x and moved forward to 0.8.x or later as needed.

## 0.6.x - 2016 and earlier

- See Git commit log or https://github.com/digitalbazaar/forge.
