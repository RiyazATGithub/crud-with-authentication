const express = require('express')
const app = express()
const data = require('./data.json')
const jwt = require('jsonwebtoken');
const jwtMiddleware = require('./tokenVerify')
const path = require('path')
const fs = require('fs')
const bcrypt = require('bcrypt')
const { v4: uuidv4 } = require('uuid');
const swaggerjsdoc = require('swagger-jsdoc')
const swaggeruiexpress = require('swagger-ui-express')
const YAML = require('yamljs')

const swaggerDoc = YAML.load(path.join(__dirname, 'swagger.yaml'))
app.use(express.json())

// serve Swagger documentation

app.use('/api-docs/', swaggeruiexpress.serve, swaggeruiexpress.setup(swaggerDoc))

// creating token for user while login


app.post('/api/login', async (req, res) => {

    const { email, password } = req.body
    if (!email || !password)
        res.send('email or password missing')

    const users = data.find(user => user.email === email)

    if (!users) return res.status(404).send('user not found')


    const isPasswordValid = await bcrypt.compare(password, users.password);

    if (!isPasswordValid) {
        return res.status(400).send('Password does not match');
    }


    const token = jwt.sign({ email: users.email, id: users.id }, 'secretKey');

    res.send(token);




})

// signing up new user

app.post('/api/register', (req, res) => {
    const { email, password } = req.body
    if (!email || !password)
        return res.status(404).send('user invalid')
    const filePath = path.join(__dirname, 'data.json')
    fs.readFile(filePath, 'utf-8', (err) => {
        if (err) return res.status(404).send('error reading file')

        if (data) {
            const userExist = data.find((user) => user.email === email)

            if (userExist) return res.status(404).send('user already exist')
        }

        bcrypt.hash(password, 5, (err, hashed) => {
            if (err)
                return res.status(404).send('error encrypt')
            const newUser = {
                id: uuidv4(),
                email,
                password: hashed
            }

            data.push(newUser)


            fs.writeFile(filePath, JSON.stringify(data, null, 2), (err) => {
                if (err) return res.status(404).send('invalid data')
                res.send('user created')


            })

        })

    })
})

// Read user details using get

app.get('/api/userdetails/:id', jwtMiddleware, (req, res) => {


    const user = data.find((user) => user.id === req.params.id);

    if (!user) {
        return res.status(404).send('User not found')
    }

    res.status(200).json(user);
});



// update using put method

app.put('/api/update/:id', jwtMiddleware, (req, res) => {
    const newObj = req.body;

    const filePath = path.join(__dirname, 'data.json')
    console.log(`reading file:${filePath}`);

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.send('file cannot read')

        const users = JSON.parse(data)

        let user = users.find((user) => user.email === req.body.email)

        if (!user) return res.send('user not found')


        // to update the value in user
        Object.assign(user, newObj)



        fs.writeFile(filePath, JSON.stringify(users, null, 2), (err) => {

            // console.log(JSON.stringify(user,null,2));
            if (err) return res.send('not updated')
            res.send('updated')

        })

    })

});

// Delete using delete method

app.delete('/api/delete/:id', jwtMiddleware, (req, res) => {

    const filePath = path.join(__dirname, 'data.json')
    console.log(`reading file: ${filePath}`);

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.send('file cannot read')

        const users = JSON.parse(data)

        const user = users.find((user) => user.id === req.params.id)
        console.log(req.params.id);
        if (!user) return res.send('user not found')

        const filterUsers = users.filter((user) => user.id !== req.params.id)

        fs.writeFile(filePath, JSON.stringify(filterUsers, null, 2), (err) => {
            if (err) return res.send('err')
            res.send('deleted successfully')
        })
    })
})

// listening the port

app.listen(3000, () => {
    console.log('listening 3000');
})