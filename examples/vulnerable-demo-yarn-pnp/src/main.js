// Yarn PnP golden demo (M7c): the same positive verdict as the npm/pnpm
// lodash demos, but the package sources live in .yarn/cache zips (PnP
// layout) — callis extracts them content-addressed, never executes .pnp.cjs.
const _ = require("lodash");
const greeting = _.template("Hello <%= name %>")({ name: "world" });
console.log(greeting);
