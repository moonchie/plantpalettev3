const mongoose = require("mongoose");
const Plant = require("../models/plant-model.js");


// connect to database
// this same chunk is in app.js
mongoose.Promise = Promise;
mongoose // make sure to connect to same DB as in app.js
  .connect('mongodb://localhost/TempPlants', {useMongoClient: true})
  .then(() => {
    console.log('Connected to Mongo!')
  }).catch(err => {
    console.error('Error connecting to mongo', err)
  });


  // ----------- CREATE ------------------
Plant.create(plantData)                                       //use the Book model
    .then((plants) => {
        console.log(`Created ${plants.length} plants in the dataBase`);
    })
    .catch((err) => {
        console.log("Create plants FAIL!")
    });