function express() {
  const app = {
    routes: [],
    get(path, handler) {
      this.routes.push({ method: "GET", path, handler });
      return this;
    },
    post(path, handler) {
      this.routes.push({ method: "POST", path, handler });
      return this;
    },
    listen() {
      return this;
    },
  };
  return app;
}
module.exports = express;
