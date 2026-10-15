function doWork() {
  return 42;
}
// Vulnerable logic executes at import time (no exported call required).
const warm = doWork();
export { doWork };
