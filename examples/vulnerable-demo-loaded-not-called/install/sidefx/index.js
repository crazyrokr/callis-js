function leak() {
  return "leaked";
}
// Import-time side effect (runs on require, but is not the advisory target call).
const boot = 1;
module.exports = { leak };
