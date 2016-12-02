/**
 * Prepares bundle for Node Forge Library based on OS platform.
 */
const os = require('os');
const exec = require('child_process').exec;

/**
 * Remove first two arguments in the array which represent execution path and file path.
 * https://nodejs.org/docs/latest/api/process.html#process_process_argv
 *
 * @type {Array.<string>} Command line arguments
 */
var commandLineArgs = process.argv.slice(2);

//If OS is windows, use `r.js.cmd` to run the optimization. In other OS, use `r.js` command.
if (os.platform() === 'win32') {
  exec('r.js.cmd ' + commandLineArgs.join(' '));
} else {
  exec('r.js ' + commandLineArgs.join(' '));
}
