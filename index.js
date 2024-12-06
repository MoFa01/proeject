const express = require('express');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URL = "mongodb+srv://GP:gp12345@cluster0.a4hua.mongodb.net/your_database_name"; // Replace with your database name


const path = require('path');

//console.log(path.dirname(__filename));

const tempFileName ="file:///" + __dirname + "/" + "uploads/" + "lec 1.pdf";
console.log(tempFileName);
// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
