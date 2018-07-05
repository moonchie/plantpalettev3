const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const plantSchema = new Schema ({
  // updated 05/07
  commonName: { type: String, required: true },
  scientificName: {type: String},
  family: {type: String},
  plantType: [
    {type: String}
    ],
  location: [{type: String}],
  sun: [
    { type: String }
  ],
  water: [
    { type: String }
  ],
  growthRate: { type: String },
  maxHeightInFeet: { type: String },
  toxicity: {type: String },
  fertilityRequirement: {type: String},
  bloomPeriod: {type: String},
  pictureUrl: { type: String}
}, {
  // additional settings for schema here

  timestamps: true
});

const Plant = mongoose.model("Plants", plantSchema);

module.exports = Plant;
