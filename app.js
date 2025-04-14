const express = require('express')
const app = express()
const mongoose = require('mongoose')
const {mongoUrl} = require('./keys')
const cors = require('cors')
const PORT = 3005;

app.use(cors())

const path = require('path')

require('./models/model')
require('./models/post')

app.use(express.json())
app.use(require('./routes/auth'))
app.use(require('./routes/createPost'))
app.use(require('./routes/user'))

mongoose.connect(mongoUrl)
mongoose.connection.on("connected",()=> {
    console.log("mongo connected successfully")
})
mongoose.connection.on("error",()=> {
    console.log("error in coonnect")
})

app.listen(PORT, ()=> {
    console.log(`server is running on ${PORT}`)
})