const express = require("express");
const _ = require("lodash");
const greeting = _.template("Hello <%= name %>")({ name: "world" });
const app = express();
app.get("/report", (req, res) => {
  res.send(_.template("Hello <%= name %>")({ name: "world" }));
});
app.listen(3000);
console.log(greeting);
