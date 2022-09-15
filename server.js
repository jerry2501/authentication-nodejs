const express = require("express")
var bodyParser = require("body-parser")
const app = express()
const mysql = require("mysql")
const bcrypt = require("bcrypt")
var passwordValidator = require('password-validator');
require("dotenv").config()


var schema = new passwordValidator();
const DB_HOST = process.env.DB_HOST
const DB_USER = process.env.DB_USER
const DB_PASSWORD = process.env.DB_PASSWORD
const DB_DATABASE = process.env.DB_DATABASE
const DB_PORT = process.env.DB_PORT

// Add properties to it
schema
    .is().min(8)                                    // Minimum length 8
    .is().max(100)                                  // Maximum length 100
    .has().uppercase()                              // Must have uppercase letters
    .has().lowercase()                              // Must have lowercase letters
    .has().digits(1)                                // Must have at least 1 digits
    .has().not().spaces()                           // Should not have spaces

const db = mysql.createPool({
    connectionLimit: 100,
    host: DB_HOST,       //This is your localhost IP
    user: DB_USER,         // "newuser" created in Step 1(e)
    password: DB_PASSWORD,  // password for the new user
    database: DB_DATABASE,      // Database name
    port: DB_PORT             // port name, "3306" by default
})

//connection with DB
db.getConnection((err, connection) => {
    if (err) throw (err)
    console.log("DB connected successful: " + connection.threadId)
})

//For starting express server
const port = process.env.PORT
app.listen(port,
    () => console.log(`Server Started on port ${port}...`))

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
// app.use(express.json())
//middleware to read req.body.<params>
//CREATE USER
app.post("/createUser", async (req, res) => {
    const user = req.body.name;
    if (!schema.validate(req.body.password)) {
        //res.send('/public/')
        res.json({ "password": 'Password should contain atleast 1 capital,1 digit and small case letters!!' });
    }
    else {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        db.getConnection(async (err, connection) => {
            if (err) throw (err)
            const sqlSearch = "SELECT * FROM newusers WHERE username = ?"
            const search_query = mysql.format(sqlSearch, [user])
            const sqlInsert = "INSERT INTO newusers VALUES (?,?)"
            const insert_query = mysql.format(sqlInsert, [user, hashedPassword])
            // ? will be replaced by values
            // ?? will be replaced by string 
            await connection.query(search_query, async (err, result) => {
                if (err) throw (err)
                console.log("------> Search Results")
                console.log(result.length)
                if (result.length != 0) {
                    connection.release()
                    console.log("------> User already exists")
                    res.sendStatus(409)
                }
                else {
                    await connection.query(insert_query, (err, result) => {
                        connection.release()
                        if (err) throw (err)
                        console.log("--------> Created new User")
                        console.log(result.insertId)
                        res.sendStatus(201)
                    })
                }
            }) //end of connection.query()
        })
    }
    //end of db.getConnection()
}) //end of app.post()

app.use("/public", express.static(`${process.cwd()}/public`));

app.get("/", function (req, res) {
    res.sendFile(process.cwd() + "/public/index.html");
});


//LOGIN (AUTHENTICATE USER)
app.post("/login", (req, res) => {
    const user = req.body.names
    const password = req.body.passwords
    if (!schema.validate(req.body.passwords)) {
        //res.send('/public/')
        res.json({ "password": 'Password should contain atleast 1 capital,1 digit and small case letters!!' });
    }
    else {
        db.getConnection(async (err, connection) => {
            if (err) throw (err)
            const sqlSearch = "Select * from newusers where username = ?"
            const search_query = mysql.format(sqlSearch, [user])
            await connection.query(search_query, async (err, result) => {
                connection.release()

                if (err) throw (err)
                if (result.length == 0) {
                    console.log("--------> User does not exist")
                    res.sendStatus(404)
                }
                else {
                    const hashedPassword = result[0].password
                    console.log(password)
                    //get the hashedPassword from result    
                    if (await bcrypt.compare(password, hashedPassword)) {
                        console.log("---------> Login Successful")
                        //res.send(`${user} is logged in!`)
                        res.redirect('/public/welcome.html')
                    }
                    else {
                        console.log("---------> Password Incorrect")
                        res.send("Password incorrect!")
                    } //end of bcrypt.compare()  
                }//end of User exists i.e. results.length==0 
            }) //end of connection.query()
        }) //end of db.connection()
    }

}) //end of app.post()

