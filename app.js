const express = require('express')
const sqlite3 = require('sqlite3')
const {open} = require('sqlite')
const path = require('path')
const bcrypt = require('bcrypt')
const app = express()

app.use(express.json())

const dbPath = path.join(__dirname, 'userData.db')
let db = null

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })
    app.listen(3000, () => {
      console.log('Listening on Port 3000...')
    })
  } catch (error) {
    console.log(`Database Error: ${error.message}`)
  }
}

initializeDbAndServer()

const validatePassword = async (inputPassword, hashedPassword) => {
  return await bcrypt.compare(inputPassword, hashedPassword)
}

app.post('/register', async (request, response) => {
  try {
    const {username, name, password, gender, location} = request.body
    const hashedPassword = await bcrypt.hash(password, 10)

    const queryForUser = 'SELECT * FROM user WHERE username = ?'
    const isUserExist = await db.get(queryForUser, [username])

    if (isUserExist) {
      response.status(400).send('User already exists')
    } else {
      if (password.length < 5) {
        response.status(400).send('Password is too short')
      } else {
        const registerQuery = `
          INSERT INTO user(username, name, password, gender, location)
          VALUES(?, ?, ?, ?, ?);
        `
        await db.run(registerQuery, [
          username,
          name,
          hashedPassword,
          gender,
          location,
        ])
        response.status(200).send('User created successfully')
      }
    }
  } catch (error) {
    console.log(`Error during user registration: ${error.message}`)
    response.status(500).send('Internal Server Error')
  }
})

app.post('/login', async (request, response) => {
  try {
    const {username, password} = request.body
    const queryForUser = 'SELECT * FROM user WHERE username = ?'
    const user = await db.get(queryForUser, [username])

    if (!user) {
      response.status(400).send('Invalid user')
    } else {
      const isValidPassword = await validatePassword(password, user.password)

      if (!isValidPassword) {
        response.status(400).send('Invalid password')
      } else {
        response.status(200).send('Login success!')
      }
    }
  } catch (error) {
    response.status(500).send('Internal Server Error')
  }
})

app.put('/change-password', async (request, response) => {
  try {
    const {username, oldPassword, newPassword} = request.body
    const hashedNewPassword = await bcrypt.hash(newPassword, 10)

    const queryForUser = 'SELECT * FROM user WHERE username = ?'
    const user = await db.get(queryForUser, [username])

    if (!user) {
      response.status(400).send('Invalid user')
    } else {
      const isValidPassword = await validatePassword(oldPassword, user.password)

      if (!isValidPassword) {
        response.status(400).send('Invalid current password')
      } else {
        if (newPassword.length < 5) {
          response.status(400).send('Password is too short')
        } else {
          const updatePasswordQuery =
            'UPDATE user SET password = ? WHERE username = ?'
          await db.run(updatePasswordQuery, [hashedNewPassword, username])
          response.status(200).send('Password updated')
        }
      }
    }
  } catch (error) {
    response.status(500).send('Internal Server Error')
  }
})

module.exports = app
