const _ = require("lodash");
const _es = require("lodash-es");
const a = _.template("Hi <%= n %>")({ n: 1 });
const b = _es.template("Hi <%= n %>")({ n: 2 });
console.log(a, b);
