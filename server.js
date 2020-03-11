// EXPRESS 
const express = require('express');
const http = require('http');
const cors = require('cors');
const bodyParser = require('body-parser');

const PORT_SERVER = '8000';

const app = express();

const router = require('./api/router');

require('dotenv').config();

app.use(bodyParser.urlencoded({limit: '15mb', extended: false}));
app.use(bodyParser.json({limit:'15mb'}));

app.use(cors());
app.options('*', cors());

app.set('port', PORT_SERVER);
app.set('host', '127.0.0.1');

app.use('/api', router);

const server = http.createServer(app);

server.listen(PORT_SERVER, ()=>{console.log(PORT_SERVER)});

