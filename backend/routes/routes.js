const express = require("express")
const mongoose = require("mongoose")
const routes = express.Router()
const db = require("../database/db.js")
const bcrypt = require("bcrypt")
const jwt = require('jsonwebtoken');
const config = require('../config/config.js')

let getHashedPassword = (password) => {
    return new Promise(function(resolve){
        bcrypt.genSalt(10, function(err, salt) {
            bcrypt.hash(password, salt, function(err, hash) {
                resolve(hash)
            });
        });        
    })
}

let comparePassword = (passwordInput, passwordDB) => {
    return new Promise(function(resolve) {
        bcrypt.compare(passwordInput, passwordDB, function(err, res) {
            resolve(res)
        });
    })    
}


let usersSchema = new mongoose.Schema({
    id: Number,
    name: String,
    email: String,
    password: String
})

let usersModel = new mongoose.model("users", usersSchema)

let contactsSchema = new mongoose.Schema({
    id: Number,
    name: String,
    email: String,
    user_affiliate: Number
})

let contactsModel = new mongoose.model("contacts", contactsSchema)

routes.use("/sign-up", async function(req, res, next) {
    try {
        let results = await usersModel.find({email: req.body.email})
        if (!results.length) {
            next()
        } else {
            res.status(200)
            res.send("Exists")
        }
    } catch (err) {
        res.status(500)
        res.send("Failure")
    }   
})

routes.post("/sign-up", async function(req, res) {
    let newUser = new usersModel({
        id: Date.now(),
        name: req.body.name,
        email: req.body.email,
        password: await getHashedPassword(req.body.password)
    })

    try {
        await newUser.save()
        let insertedUser = await usersModel.find({email: req.body.email})
        
        let token = jwt.sign({id: insertedUser[0].id, name: insertedUser[0].name}, config.secret, {expiresIn: 86400})
        res.status(200)
        res.send({auth: true, token: token})        
    } catch (err) {
        res.status(500)
        res.send("Failure")
        throw err
    }    
})

routes.post("/sign-in", async function(req, res) {
    try {
        let results = await usersModel.find({email: req.body.email})
        if (results.length) {
            let valid = await comparePassword(req.body.password, results[0].password)

            if (!valid) {
                res.status(500)
                return res.send("Failed")
            } else if (valid) {
                let token = jwt.sign({id: results[0].id, name: results[0].name}, config.secret, {expiresIn: 86400})
                res.status(200)
                return res.send({auth: true, token: token})
            }
        } else {
            res.status(500)
            res.send("Failed")
        } 
    } catch (err) {
        res.status(500)
        res.send("Failure")
        throw err 
    }       

})

routes.use("/delete/:id", function(req, res, next) {
    try {
        let verified = jwt.verify(req.headers.token, config.secret)

        if(req.params.id == verified.id && Date.now()/1000 <= verified.exp) {
            next()
        } else {
            res.status(403)
            res.send()
        }
    } catch (err) {
        res.status(500)
        res.send("Failure")
        throw err
    }
    
})   

routes.delete("/delete/:id", async function(req, res) {
    try{
        await usersModel.deleteOne({id: req.params.id})
        res.status(200)
        res.send("Success")
    } catch (err) {
        res.status(500)
        res.send("Failure")
        throw err
    }  
})



routes.use("/add-new-contact", function(req, res, next){
    try {
        let verified = jwt.verify(req.headers.token, config.secret)
    
        if(req.body.user_affiliate === verified.id && Date.now()/1000 <= verified.exp) {
            next()
        } else {
            res.status(403)
            res.send()
        }
    } catch (err) {
        res.status(500)
        res.send("Failure")
        throw err
    }    
})

routes.post("/add-new-contact", async function(req, res) {
    let newContact = new contactsModel({
        id: Date.now(),
        name: req.body.name,
        email: req.body.email,
        user_affiliate: req.body.user_affiliate
    })

    try {
        await newContact.save()
        res.status(200)
        res.send("Success")
    } catch (err) {
        res.status(500)
        res.send("Failure")
        throw err
    }    
})


routes.use("/get-contacts/:id", function(req, res, next) {
    try {
        let verified = jwt.verify(req.headers.token, config.secret)

        if(req.params.id == verified.id && Date.now()/1000 <= verified.exp) {
            next()
        } else {
            res.status(403)
            res.send()
        }
    } catch (err){
        res.status(500)
        res.send("Failure")
        throw err
    }    
})   

routes.get("/get-contacts/:id", async function(req, res) {
    try {
        let results = await contactsModel.find({user_affiliate: req.params.id})
        res.status(200)
        res.send(results)
    } catch(err) {
        res.status(500)
        res.send("Failure")
        throw err
    }    
})



routes.use("/deletingSingleContact", function(req, res, next){
    try {
        let verified = jwt.verify(req.headers.token, config.secret)

        if(req.body.user_affiliate === verified.id && Date.now()/1000 <= verified.exp) {
            next()
        } else {
            res.status(403)
            res.send()
        }
    } catch (err) {
        res.status(500)
        res.send("Failure")
        throw err
    }   
})

routes.post("/deleteSingleContact", async function(req, res) {
    try {
        await contactsModel.deleteOne({name: req.body.name, email: req.body.email, user_affiliate: req.body.user_affiliate})
        res.status(200)
        res.send("Contact deleted successfully")
    } catch (err) {
        res.status(500)
        res.send("Failure")
        throw err
    }  
})

routes.use("/deleteAllContacts/:id", function(req, res, next) {
    try {
        let verified = jwt.verify(req.headers.token, config.secret)

        if(req.params.id == verified.id && Date.now()/1000 <= verified.exp) {
            next()
        } else {
            res.status(403)
            res.send()
        }
    } catch (err) {
        res.status(500)
        res.send("Failure")
        throw err
    }   
})

routes.delete("/deleteAllContacts/:id", async function(req, res) {
    try {
        await contactsModel.deleteMany({user_affiliate: req.params.id})
        res.status(200)
        res.send("Contacts deleted successfully")
    } catch (err) {
        res.status(500)
        res.send("Failure")
        throw err
    }   
})

module.exports = routes