const _ = require("lodash");
// Only the safe export is used: the mapped target (template) is never reached.
console.log(_.chunk([1, 2, 3, 4], 2));
