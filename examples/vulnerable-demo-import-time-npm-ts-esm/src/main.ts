// Bare side-effect import: the package's import-time code runs, no exported
// function is ever called.
import "impfx";

console.log("loaded");
