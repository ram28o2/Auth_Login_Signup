const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const dotenv = require('dotenv').config();


const app = express();
const PORT = process.env.PORT;

console.log("hello");

app.use(cors()); 
app.use(helmet());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

mongoose
    .connect(process.env.MONGO_URI)
    .then(() => console.log("DB Connected"))
    .catch((err) => console.log(err));


app.get('/' , (req,res) =>{
    res.json({message : "Connected to the server"});
})

app.listen(PORT , (req,res) =>{
    console.log(`App is listening at ${PORT}`);
})