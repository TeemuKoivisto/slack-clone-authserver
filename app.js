"use strict";

/**
 * If no NODE_ENV has been set load env variables from .env -file
 */
if (!process.env.NODE_ENV) {
  require("dotenv").config();
}

const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();

const port = process.env.PORT || 3332;

/**
 * If NODE_ENV is not production use morgan to log all queries to the console
 */
if (process.env.NODE_ENV !== "production") {
  const logger = require("morgan");
  app.use(logger("dev"));
}

/**
 * Body parser parses the request body from http-requests that have it.
 */
app.use(bodyParser.urlencoded({
  extended: true,
}));
app.use(bodyParser.json());
/**
 * CORS is shorthand for "Cross-Origin-Resource-Sharing" which means that this API
 * will accept request made outside its native port.
 */
// app.use(cors());
app.use(cors({ credentials: true, origin: ["http://localhost:3333", "https://slack-clone-extreme.herokuapp.com"] }));

/**
 * This loads the routes defined in ./config/routes to the root path "".
 */
app.use("", require("./config/routes"));

/**
 * If module has no parent which means that it has been loaded directly with 'node app.js'
 * then start up the server. This is used for testing when starting up the server is
 * unpreferred when loading this file with 'require("app")'.
 */
if (!module.parent) {
  app.listen(port, (err) => {
    if (err) {
      console.log(err);
    } else {
      console.log(`App is listening on port ${port}`);
    }
  });

  process.on("exit", () => {
    app.close();
    process.exit();
  });
}

module.exports = app;
