import { Router } from 'express';
import { body, header } from 'express-validator';
import controller, { validate, fetchUserByEmailOrID } from './controller.js';

const routes = Router({ strict: true });

// regla de validacion de token
const tokenValidation = (isRefresh = false) => {
    let refreshText = isRefresh ? 'Refresh' : 'Authorization';

    return [
        header('Authorization', `Please provide your ${refreshText} token`)
            .exists()
            .not()
            .isEmpty()
            .custom((value, { req }) => {
                if (!value.startsWith('Bearer') || !value.split(' ')[1]) {
                    throw new Error(`Invalid ${refreshText} token`);
                }
                if (isRefresh) {
                    req.headers.refresh_token = value.split(' ')[1];
                    return true;
                }
                req.headers.access_token = value.split(' ')[1];
                return true;
            }),
    ];
};

// Crear nuevo usuario
routes.post(
    '/create',
    [
        body('name')
            .trim()
            .not()
            .isEmpty()
            .withMessage('El nombre no puede ser vacio.')
            .escape(),
        body('email', 'Correo invalido.')
            .trim()
            .isEmail()
            .custom(async (email) => {
                const isExist = await fetchUserByEmailOrID(email);
                if (isExist.length)
                    throw new Error(
                        'el usuario con el correo ya existe'
                    );
                return true;
            }),
        body('password')
            .trim()
            .isLength({ min: 4 })
            .withMessage('el pasword debe de contener al menos 4 letras'),
    ],
    validate,
    controller.signup
);

// Login user through email and password
routes.post(
    '/login',
    [
        body('email', 'Email invalido')
            .trim()
            .isEmail()
            .custom(async (email, { req }) => {
                const isExist = await fetchUserByEmailOrID(email);
                if (isExist.length === 0)
                    throw new Error('El email no esta registrado.');
                req.body.user = isExist[0];
                return true;
            }),
        body('password', 'password incorrecto').trim().isLength({ min: 4 }),
    ],
    validate,
    controller.login
);

// obtienen todo los usuarios
routes.get('/users', tokenValidation(), validate, controller.getUsers);

//obtiene usuario por id
routes.get('/profile/:id', tokenValidation(), validate, controller.getUser);

//elimina usuario por id
routes.delete('/delete/:id', tokenValidation(), validate, controller.deleteUser);

//elimina usuario por id
routes.delete('/update', tokenValidation(), validate, controller.updateUser);
//refresca el token
routes.get(
    '/refresh',
    tokenValidation(true),
    validate,
    controller.refreshToken
);

export default routes;
