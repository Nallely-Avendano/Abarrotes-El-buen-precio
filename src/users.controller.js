const { Router } = require('express');
const { isEmail } = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./user.model');

const BCRYPT_ROUNDS = 10;
const router = Router();

function validaName(name) {
    return typeof name == 'string' && name.length > 0;
}

function validEmail(email) {
    return typeof email == 'string'
        && email.length > 0
        && isEmail(email);
}

function validPassword(password) {
    if (typeof password != 'string' || password.length < 8) {
        return false;
    }
    const hasNumber = /[0-9]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasUppercase = /[A-Z]/.test(password);
    return hasNumber && hasLowercase && hasUppercase;
}

function validPhone(phone) {
    return typeof phone == 'string' && /^\d{10}$/.test(phone);
}

function validAddress(address) {
    return typeof address == 'string' && address.length > 0;
}

router.post('/auth/signup', (req, res) => {
    const { name, email, password, phone, address, } = req.body || {};
    if (
        !validaName(name)
        || !validEmail(email)
        || !validPassword(password)
        || !validPhone(phone)
        || !validAddress(address)
    ) {
        res.status(400).send({ error: 'Datos de registro inválidos' });
        return;
    }
    Promise.all([
        bcrypt.hash(password, BCRYPT_ROUNDS),
        User.findOne({ email }),
    ]).then(([hashedPassword, user]) => {
        if (user) {
            res.status(400).send({ error: 'Email ya registrado'} );
            throw new Error('');
        }
        return User.create({
            name, email,
            password: hashedPassword,
            phone, address,
        });
    }).then(() => {
        res.status(201).send({ message: 'Usuario creado exitosamente' });
    }).catch(error => {
        if (error.message == '') {
            return;
        }
        res.status(500).send({ error: 'Error del servidor' });
    });
});

router.post('/auth/login', (req, res) => {
    const { email, password } = req.body || {};
    if (!validEmail(email) || !validPassword(password)) {
        res.status(401).send({ error: 'Email o contraseña inválidos' });
        return;
    }
    User.findOne({ email })
    .then(user => {
        if (!user) {
            res.status(401).send({ error: 'Email o contraseña inválidos' });
            throw new Error('');
        }
        return bcrypt.compare(password, user.password);
    }).then(isValidPassword => {
        if (isValidPassword) {
            const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.send({ token });
        } else {
            res.status(401).send({ error: 'Email o contraseña inválidos' });
        }
    }).catch(error => {
        if (error.message == '') {
            return;
        }
        res.status(500).send({ error: 'Error del servidor' });
    });
});

router.get('/users/me', (req, res) => {
    const authorization = req.headers.authorization;
    const prefix = 'Bearer ';
    if (typeof authorization != 'string' || !authorization.startsWith(prefix)) {
        res.status(401).send({ error: 'Token inválido' });
        return;
    }
    try {
        const token = authorization.slice(prefix.length);
        const { email } = jwt.verify(token, process.env.JWT_SECRET);
        User.findOne({ email })
        .then(user => {
            if (user) {
                res.send({
                    name: user.name,
                    email: user.email,
                    phone: user.phone,
                    address: user.address,
                });
            } else {
                res.status(404).send({ error: 'User not found' });
            }
        }).catch(() => {
            res.status(500).send({ error: 'Error del servidor' });
        });
    } catch (e) {
        res.status(401).send({ error: 'Token inválido' });
    }
});

module.exports = router;
