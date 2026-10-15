function template(text, options) {
  const fn = String(text).replace(/<%= (\w+) %>/g, (_m, key) => String(options ? options[key] : ""));
  return function render(extra) {
    return fn.replace(/__NAME__/, String(extra ? extra.name : ""));
  };
}
function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}
module.exports = { template, chunk };
