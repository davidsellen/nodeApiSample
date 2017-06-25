const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user) {
    const timestamp = new Date().getTime();
    return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next) {
    // user has already had their email and password auth
    // we just need to give them a token

    res.json({ token: tokenForUser(req.user) });
}

exports.signup = function(req, res, next) {
    
    const email = req.body.email;
    const password = req.body.password;
    
    if (!email || !password) {
        return res.status(422).send({ error: 'You must provide email and password'});
    }

    // see if a user with the given email exists
    const findUser = User.findOne({ email: email });
    
    findUser.then(function(foundUser) {        

        // if a user with email does exist, return an error
        if (foundUser) {
            return res.status(422).send({error: 'Email is in use' });
        }

        // if a user with email does not exist, create and save user record
        const user = new User({ 
            email: email, 
            password: password 
        });

        const saveUser = user.save();
        
        // respond to request indicating the user was created
        saveUser.then(function(saveResult) {
            res.json({ token: tokenForUser(user) });
        }, function(err) {
            if (err) { return next(err); }
        });

    }, function(err){
        if (err) { return next(err); }
    });    
}