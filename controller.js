import bcrypt from 'bcrypt';
import { createHash } from 'crypto';
import { validationResult, matchedData } from 'express-validator';
import { generateToken, verifyToken } from './tokenHandler.js';
import DB from './dbConnection.js';

const validation_result = validationResult.withDefaults({
    formatter: (error) => error.msg,
});

export const validate = (req, res, next) => {
    const errors = validation_result(req).mapped();
    if (Object.keys(errors).length) {
        return res.status(422).json({
            status: 422,
            errors,
        });
    }
    next();
};

// valida si el correo existe en la base de datos
export const fetchUserByEmailOrID = async (data, isEmail = true) => {
    let sql = 'SELECT * FROM `users` WHERE `email`=?';
    if (!isEmail)
        sql = 'SELECT `id` ,`name`, `email` FROM `users` WHERE `id`=?';
    const [row] = await DB.execute(sql, [data]);
    return row;
};

// Obtiene todos los usuarios de la base de datos
export const getUsers = async () => {
    let sql = 'SELECT * FROM `users`';
    const [row] = await DB.execute(sql);
    return row;
};

// Elimina usuario de la base de datos
export const deleteUsers = async (data) => {
    let sql = 'DELETE FROM `users` WHERE `id`=?';
    const [row] = await DB.execute(sql, [data]);
    return row;
};

// Actualiza el usuario de la base de datos
export const updateUser = async (name, email, password,id) => {
    let sql = 'UPDATE users SET  `name`=?, `password`=?, updated_at=current_timestamp() WHERE `id`=?';
    const [row] = await DB.execute(sql, [name, email, hashPassword,id]);
    return row;
};

export default {
    signup: async (req, res, next) => {
        try {
            const { name, email, password } = matchedData(req);

            const saltRounds = 10;
            // Hash del password
            const hashPassword = await bcrypt.hash(password, saltRounds);

            // resultado
            const [result] = await DB.execute(
                'INSERT INTO `users` (`name`,`email`,`password`) VALUES (?,?,?)',
                [name, email, hashPassword]
            );
            res.status(201).json({
                status: 201,
                message: 'Se a guardado el usuario exitosamente.',
                user_id: result.insertId,
            });
        } catch (err) {
            next(err);
        }
    },

    login: async (req, res, next) => {
        try {
            const { user, password } = req.body;
            const verifyPassword = await bcrypt.compare(
                password,
                user.password
            );
            if (!verifyPassword) {
                return res.status(422).json({
                    status: 422,
                    message: 'error de login',
                });
            }

            // Genera acceso and actualiza Token
            const access_token = generateToken({ id: user.id });
            const refresh_token = generateToken({ id: user.id }, false);

            const md5Refresh = createHash('md5')
                .update(refresh_token)
                .digest('hex');

            // token en formato md5
            const [result] = await DB.execute(
                'INSERT INTO `tokens` (`user_id`,`token`) VALUES (?,?)',
                [user.id, md5Refresh]
            );

            if (!result.affectedRows) {
                throw new Error('fallo el la actualizacion del token.');
            }
            res.json({
                status: 200,
                access_token,
                refresh_token,
            });
        } catch (err) {
            next(err);
        }
    },

    getUser: async (req, res, next) => {
        try {
            //Verifica el acceso del token
            const data = verifyToken(req.headers.access_token);
            if (data?.status) return res.status(data.status).json(data);
            // fetching user by the `id` (column)
            const user = await fetchUserByEmailOrID(req.params.id, false);
            if (user.length !== 1) {
                return res.status(404).json({
                    status: 404,
                    message: 'Usuario no encontrado',
                });
            }
            res.json({
                status: 200,
                user: user[0],
            });
        } catch (err) {
            next(err);
        }
    },
    getUsers: async (req, res, next) => {
        try {
            //Verifica el acceso del token
            const data = verifyToken(req.headers.access_token);
            if (data?.status) return res.status(data.status).json(data);
            // fetching user by the `id` (column)
            const user = await getUsers();
            if (user.length < 0) {
                return res.status(404).json({
                    status: 404,
                    message: 'No existen usuarios',
                });
            }
            res.json({
                status: 200,
                users: user,
            });
        } catch (err) {
            next(err);
        }
    },
     deleteUser: async (req, res, next) => {
        try {
            //Verifica el acceso del token
            const data = verifyToken(req.headers.access_token);
            if (data?.status) return res.status(data.status).json(data);
            // fetching user by the `id` (column)
            const user = await deleteUsers(req.params.id);
            res.json({
                status: 200,
                resultado: user,
            });
        } catch (err) {
            next(err);
        }
    },
    
    updateUser: async (req, res, next) => {
        try {
            //Verifica el acceso del token
            const { id , name, email, password } = matchedData(req);
            if (data?.status) return res.status(data.status).json(data);
            // fetching user by the `id` (column)
            const user = await deleteUsers(name, email, password, id);
            res.json({
                status: 200,
                resultado: user,
            });
        } catch (err) {
            next(err);
        }
    },
    refreshToken: async (req, res, next) => {
        try {
            const refreshToken = req.headers.refresh_token;
            // verifica el refresco del token
            const data = verifyToken(refreshToken, false);
            if (data?.status) return res.status(data.status).json(data);

            //convierte a md5
            const md5Refresh = createHash('md5')
                .update(refreshToken)
                .digest('hex');

            // encontrando el token en base
            const [refTokenRow] = await DB.execute(
                'SELECT * from `tokens` WHERE token=?',
                [md5Refresh]
            );

            if (refTokenRow.length !== 1) {
                return res.json({
                    status: 401,
                    message: 'Unauthorized: token invalido',
                });
            }

            // Genera el acceso con token
            const access_token = generateToken({ id: data.id });
            const refresh_token = generateToken({ id: data.id }, false);

            const newMd5Refresh = createHash('md5')
                .update(refresh_token)
                .digest('hex');

            //reemplaza el antiguo token por uno nuevo
            const [result] = await DB.execute(
                'UPDATE `tokens` SET `token`=? WHERE `token`=?',
                [newMd5Refresh, md5Refresh]
            );

            if (!result.affectedRows) {
                throw new Error('Fallo al actualizar el token.');
            }

            res.json({
                status: 200,
                access_token,
                refresh_token,
            });
        } catch (err) {
            next(err);
        }
    },
};
