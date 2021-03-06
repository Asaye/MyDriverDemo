// MyDriverDemo/App.js
const MyDriver = require('./MyDriver');
const db = new MyDriver();

const config = {
   "host": "localhost", 
   "port": 3306,
   "user": "root",
   "password": "root",
   "database": "mydb"
};

db.connect(config, (err, res) => {
   if (err) {
      console.log(err);
      return;
   }
   console.log(res);    // connected
});

db.query("select * from customers", (err, res) => {
   if (err) {
      console.log("error occurred during query.");
      return;
   }
   console.log("Result set in JSON format is:");
   console.log(res);
   db.close();
});