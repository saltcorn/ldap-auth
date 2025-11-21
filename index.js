const LdapStrategy = require("passport-ldapauth");
const User = require("@saltcorn/data/models/user");
const Workflow = require("@saltcorn/data/models/workflow");
const Form = require("@saltcorn/data/models/form");
const db = require("@saltcorn/data/db");
const bunyan = require("bunyan");

const { getState } = require("@saltcorn/data/db/state");

const authentication = (config) => {
  const scLogLevel = getState().logLevel;
  const bLogLevel =
    scLogLevel >= 5
      ? bunyan.TRACE
      : scLogLevel === 4
      ? bunyan.DEBUG
      : bunyan.ERROR;
  var logger = bunyan.createLogger({
    name: "saltcorn-ldap",
    level: bLogLevel,
  });
  return {
    ldap: {
      label: "LDAP",
      setsUserAttribute: "ldapdn",
      postUsernamePassword: true,
      usernameLabel: "UID",
      strategy: new LdapStrategy(
        {
          server: { ...config, log: logger },
          usernameField: "email",
          passwordField: "password",
        },
        function (user, cb) {
          User.findOrCreateByAttribute("ldapdn", user.dn, {
            email: user.mail || "",
          }).then((u) => {
            return cb(null, u.session_object);
          });
        }
      ),
    },
  };
};
const configuration_workflow = () => {
  return new Workflow({
    steps: [
      {
        name: "LDAP configuration",
        form: () =>
          new Form({
            labelCols: 3,
            fields: [
              {
                name: "url",
                label: "Server URL",
                type: "String",
                required: true,
              },
              {
                name: "bindDN",
                label: "Bind DN",
                type: "String",
              },
              {
                name: "bindCredentials",
                label: "Bind Credentials",
                input_type: "password",
              },
              {
                name: "searchBase",
                label: "Search Base",
                type: "String",
              },
              {
                name: "searchFilter",
                label: "Search Filter",
                type: "String",
                required: true,
              },
            ],
          }),
      },
    ],
  });
};
module.exports = {
  sc_plugin_api_version: 1,
  authentication,
  configuration_workflow,
};
