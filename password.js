const bcrypt = require("bcryptjs");

console.log(bcrypt.hashSync("123456", bcrypt.genSaltSync(10)));
