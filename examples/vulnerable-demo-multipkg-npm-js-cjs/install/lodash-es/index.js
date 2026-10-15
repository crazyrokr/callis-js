function template(text, options) {
  return String(text).replace(/<%= (\w+) %>/g, (_m, key) => String(options ? options[key] : ""));
}
module.exports = { template };
