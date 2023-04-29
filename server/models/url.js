const mongoose = require('mongoose')

// instantiate a mongoose schema
const URLSchema = new mongoose.Schema({
    urlCode: String,
    longUrl: String,
    shortUrl: String,
    date: {
        type: Date,
        default: Date.now
    }
})

// create a model from schema and export it
const Url = mongoose.model('Url', URLSchema)

module.exports = Url;







