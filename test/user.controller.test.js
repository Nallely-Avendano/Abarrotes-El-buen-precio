const request = require('supertest');
const express = require('express');
const userRouter = require('../src/users.controller');
const User = require('../src/user.model');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use('/api/v1', userRouter);
process.env.JWT_SECRET = 'testsecret';

describe('Auth Routes', () => {
    test('Signup with valid data should succeed', async () => {
        const res = await request(app)
            .post('/api/v1/auth/signup')
            .send({
                name: 'Alice',
                email: 'alice@example.com',
                password: 'Password123',
                phone: '1234567890',
                address: 'Calle sin nombre',
            });
        expect(res.statusCode).toBe(201);
        expect(res.body.message).toBe('Usuario creado exitosamente');
    });

    test('Signup with duplicate email should fail', async () => {
        await User.create({
            name: 'Alice',
            email: 'alice@example.com',
            password: 'hashedpass',
            phone: '1234567890',
            address: 'Calle sin nombre',
        });
        const res = await request(app)
            .post('/api/v1/auth/signup')
            .send({
                name: 'Alice',
                email: 'alice@example.com',
                password: 'Password123',
                phone: '1234567890',
                address: 'Calle sin nombre',
            });
        expect(res.statusCode).toBe(400);
        expect(res.body.error).toBe('Email ya registrado');
    });

    test('Login with correct credentials returns token', async () => {
        const bcrypt = require('bcrypt');
        const hashed = await bcrypt.hash('Password123', 10);
        await User.create({
            name: 'Alice',
            email: 'alice@example.com',
            password: hashed,
            phone: '1234567890',
            address: 'Calle sin nombre',
        });
        const res = await request(app)
            .post('/api/v1/auth/login')
            .send({
                email: 'alice@example.com',
                password: 'Password123'
            });
        expect(res.statusCode).toBe(200);
        expect(res.body.token).toBeDefined();
    });

    test('Get /me with valid token returns user info', async () => {
        const user = await User.create({
            name: 'Alice',
            email: 'alice@example.com',
            password: 'hashed',
            phone: '1234567890',
            address: 'Calle sin nombre',
        });
        const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, {
            expiresIn: '1h'
        });
        const res = await request(app)
            .get('/api/v1/users/me')
            .set('Authorization', `Bearer ${token}`);
        expect(res.statusCode).toBe(200);
        expect(res.body.email).toBe('alice@example.com');
        expect(res.body.name).toBe('Alice');
        expect(res.body.phone).toBe('1234567890');
        expect(res.body.address).toBe('Calle sin nombre');
    });

    test('Signup with invalid email should fail', async () => {
        const res = await request(app)
            .post('/api/v1/auth/signup')
            .send({
                name: 'Bob',
                email: 'invalid-email',
                password: 'Password123',
                phone: '1234567890',
            address: 'Calle sin nombre',
            });
        expect(res.statusCode).toBe(400);
        expect(res.body.error).toBe('Datos de registro inválidos');
    });

    test('Signup with weak password should fail', async () => {
        const res = await request(app)
            .post('/api/v1/auth/signup')
            .send({
                name: 'Bob',
                email: 'bob@example.com',
                password: 'weakpass',
                phone: '1234567890',
            address: 'Calle sin nombre',
            });
        expect(res.statusCode).toBe(400);
        expect(res.body.error).toBe('Datos de registro inválidos');
    });

    test('Signup with missing name should fail', async () => {
        const res = await request(app)
            .post('/api/v1/auth/signup')
            .send({
                email: 'bob@example.com',
                password: 'Password123',
                phone: '1234567890',
                address: 'Calle sin nombre',
            });
        expect(res.statusCode).toBe(400);
        expect(res.body.error).toBe('Datos de registro inválidos');
    });

    test('Login with wrong password should fail', async () => {
        const bcrypt = require('bcrypt');
        const hashed = await bcrypt.hash('Password123', 10);
        await User.create({
            name: 'Carol',
            email: 'carol@example.com',
            password: hashed,
            phone: '1234567890',
            address: 'Calle sin nombre',
        });
        const res = await request(app)
            .post('/api/v1/auth/login')
            .send({
                email: 'carol@example.com',
                password: 'WrongPassword'
            });
        expect(res.statusCode).toBe(401);
        expect(res.body.error).toBe('Email o contraseña inválidos');
    });

    test('Login with non-existent email should fail', async () => {
        const res = await request(app)
            .post('/api/v1/auth/login')
            .send({
                email: 'notfound@example.com',
                password: 'Password123'
            });
        expect(res.statusCode).toBe(401);
        expect(res.body.error).toBe('Email o contraseña inválidos');
    });

    test('Access /me without token should fail', async () => {
        const res = await request(app)
            .get('/api/v1/users/me');
        expect(res.statusCode).toBe(401);
        expect(res.body.error).toBe('Token inválido');
    });

    test('Access /me with invalid token should fail', async () => {
        const res = await request(app)
            .get('/api/v1/users/me')
            .set('Authorization', 'Bearer invalid.token.here');
        expect(res.statusCode).toBe(401);
        expect(res.body.error).toBe('Token inválido');
    });

    test('Access /me with valid token but user not in DB should return 404', async () => {
        const token = jwt.sign({ email: 'ghost@example.com' }, process.env.JWT_SECRET, {
            expiresIn: '1h'
        });
        const res = await request(app)
            .get('/api/v1/users/me')
            .set('Authorization', `Bearer ${token}`);
        expect(res.statusCode).toBe(404);
        expect(res.body.error).toBe('User not found');
    });

    test('Access /me with expired token should fail', async () => {
        const token = jwt.sign({ email: 'old@example.com' }, process.env.JWT_SECRET, {
            expiresIn: '-1s'
        });
        const res = await request(app)
            .get('/api/v1/users/me')
            .set('Authorization', `Bearer ${token}`);
        expect(res.statusCode).toBe(401);
        expect(res.body.error).toBe('Token inválido');
    });
});
