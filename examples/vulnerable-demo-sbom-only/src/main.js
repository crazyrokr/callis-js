const express = require("express");
const _ = require("lodash");

// Direct module-scope use of the vulnerable export (CVE-2020-8203 shape).
const greeting = _.template("Hello <%= name %>")({ name: "world" });

const app = express();
app.get("/report", (req, res) => {
  res.send(_.template("Hello <%= name %>")({ name: req.query.name || "world" }));
});
app.listen(3000);
console.log(greeting);
