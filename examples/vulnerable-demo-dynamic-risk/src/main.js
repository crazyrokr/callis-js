// Computed require: could load any installed package at runtime.
const which = process.env.WHICH || "dynpkg";
const mod = require(which);
console.log(mod);
