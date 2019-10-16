const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')

const Users = require('../users/users-model.js');
const secrets = require('../config/secrets')

// for endpoints beginning with /api/auth
router.post('/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

router.post('/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {

      if (user && bcrypt.compareSync(password, user.password)) {
        // library previous will generate token automatically
        const token = generateToken(user)

        res.status(200).json({
          message: `Welcome ${user.username}!`,
          token,
        });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// generate token user
function generateToken(user) {
  // invoke the JWT sign method
  // at least 3 params, secret used to decrypt token
  const payload = { // some props are standard: subject, username
    subject: user.id, // sub
    username: user.username,
    // ...other data
  }
  // no longer needed when we make secrets file
  // const secret = 'wsfkmwefodfcwlkemfrkf'
  const options = {
    expiresIn: '8h' // more options in library: npmjs.com
  }

  return jwt.sign(payload, secrets.jwtSecret, options)
}

module.exports = router;
