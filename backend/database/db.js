const mongoose = require("mongoose")

let connection = mongoose.connect("mongodb://localhost/AuthenticationVue", {useNewUrlParser: true, useUnifiedTopology: true});


// connection.connect()

module.exports = connection
