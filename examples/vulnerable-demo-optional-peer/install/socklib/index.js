let bu = null;
try {
  bu = require("bufferutil");
} catch (e) {
  bu = null;
}
function send(data) {
  return bu !== null ? bu.process(String(data)) : String(data);
}
module.exports = { send };
