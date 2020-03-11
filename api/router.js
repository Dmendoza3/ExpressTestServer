const app = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cypher = require('crypto');

const algorithm = 'aes-128-cbc';

require('dotenv').config();

const keyHex = Buffer.from(process.env.KEY, 'base64');
const ivHex = Buffer.from(process.env.INITVECTOR, 'base64');

const conn = mysql.createPool({
    connectionLimit: 20,
    host: 'localHost',
    port: '3306',
    user: 'root',
    password:'toor',
    database:'prueba',
    insecureAuth:true,
    multipleStatements:true
})

function encode(text){
    var cypher_ = cypher.createCipheriv(algorithm, keyHex, ivHex);
    var crypted = cypher_.update(text + '', 'utf8', 'hex');
    crypted += cypher_.final('hex');
    return crypted;
}

function decode(text){
    var decypher_ = cypher.createDecipheriv(algorithm, keyHex, ivHex);
    var decrypted = decypher_.update(text + '', 'hex','utf8');
    decrypted += decypher_.final('utf8');
    return decrypted;
}

const router = app.Router();

router.get('/', (req, res, next)=>{
    let query = 'SELECT * FROM personas ';

    conn.query(query, (error, results)=> {
        if(error){
            next(error)
        }else{
            res.status(200).json({response:results});
        }
    })
})

router.post('/post', (req, res, next)=>{
    let {nombre} = req.body;
    let query = 'INSERT INTO personas (nombre) values (?)';
    
    conn.query(query, [nombre], (error, results)=> {
        if(error){
            next(error)
        }else{
            res.status(200).json({response:true});
        }
    });
});

router.put('/update', (req, res, next)=>{
    let {idPersonas, nombre} = req.body;
    let query = 'UPDATE personas SET nombre=? WHERE (idPersonas=?)';

    conn.query(query, [nombre, idPersonas], (error, results)=> {
        if(error){
            next(error)
        }else{
            res.status(200).json({response:true});
        }
    })
});

router.put('/delete', (req, res, next)=>{
    let {idPersonas} = req.body;
    let query = 'delete from personas WHERE (idPersonas=?)';
    conn.query(query, [idPersonas], (error, results)=> {
        if(error){
            next(error)
        }else{
            res.status(200).json({response:true});
        }
    })
});

router.post('/login',(req, res, next)=>{
    let {Email} = req.body;
    let query = 'SELECT idUsuario, password, idPersonas from usuarios where Email=?';

    conn.query(query, [Email], (error, results)=> {
        if(error){
            next(error)
        }else{
            res.locals.ll= '';
            if (results.length){
                res.locals.password = results[0].password;
                res.locals.idUsuario = results[0].idUsuario;
                res.locals.idPersonas = results[0].idPersonas;
                next();
            } else {
                res.status(400).json({response:"No existe un usuario con este correo."})
            }
        }
    });
}, (req, res, next)=>{
    let { Password } = req.body;
    bcrypt.compare(Password, res.locals.password, (err, result)=>{
        if(!result){
            next(err);
        } else {
            res.status(400).json({response:"Usuario o Contraseña incorrecto."});
        }
    });
},(req, res, next)=>{
    let query = 'select idSesion from sesiones where logout is null';

    conn.query(query, (error, results)=> {
        if(error){
            next(error)
        }else{
            res.locals.ll= '';
            if (results.length){
                res.status(400).json({response:"Ya hay una sesion abierta."})
            } else {
                next();
            }
        }
    });
},(req, res, next)=>{
    var token = jwt.sign({
        idPersonas: res.locals.idPersonas,
        idUsuario: res.locals.idUsuario
    }, 
        process.env.TOKEN
    );

    let query = 'insert into sesiones (login, token) values (now(), ?)';

    conn.query(query, [token], (error, results)=> {
        if(error){
            next(error)
        }else{
            var sesionToken = encode(results.insertId);
            res.status(200).json({token:sesionToken});
        }
    });

});

router.put('/logout', (req, res,next)=>{
    if(req.headers['authorization']){
        let decodedSesion = decode(req.headers['authorization']);
    
        let query = 'update sesiones set logout=now() where idSesion=? and logout is null';
    
        conn.query(query, [decodedSesion], (error, results)=> {
            if(error){
                next(error)
            }else{
                res.status(200).json({response:decodedSesion});
            }
        });
    }else{
        res.status(400).json({response:false});
    }
});

module.exports = router