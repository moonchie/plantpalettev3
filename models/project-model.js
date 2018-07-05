const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const projectSchema = new Schema({
    projectName:{type: String, required: true },
    projectDescription: {type: String},
    location: {type: String, required: true},
    userID: { type : "ObjectId", ref: "User", required:true},
    plantArray: [{ type: "ObjectId", ref:"Plants"}],
},{
    timestamps: true
});


const Project = mongoose.model("Project", projectSchema);

module.exports = Project;