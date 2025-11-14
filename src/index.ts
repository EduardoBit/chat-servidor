import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();
import { v2 as cloudinary } from 'cloudinary';
import multer from 'multer';

// Configura Multer para guardar el archivo en memoria temporalmente
const upload = multer({ storage: multer.memoryStorage() });

const CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const API_KEY = process.env.CLOUDINARY_API_KEY;
const API_SECRET = process.env.CLOUDINARY_API_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;
const DB_PASSWORD = process.env.DB_PASSWORD;

if (!CLOUD_NAME || !API_KEY || !API_SECRET || !JWT_SECRET) {
  throw new Error(
    "Error fatal: Faltan variables de entorno críticas (Cloudinary o JWT_SECRET) en el archivo .env"
  );
}

cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || '', 
  api_key: process.env.CLOUDINARY_API_KEY || '', 
  api_secret: process.env.CLOUDINARY_API_SECRET ||'' 
});

//Configuración Inicial 
const app = express();
app.use(cors());
app.use(express.json());
const servidor = http.createServer(app);
const io = new Server(servidor, {
  cors: {
    origin: "http://localhost:5173", 
    methods: ["GET", "POST"]
  }
});


const PORT = process.env.PORT || 4000;
// Configuración de la Base de Datos 
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root', 
  password: DB_PASSWORD || '',
  database: 'chat_db'
});


// REGISTRAR un nuevo usuario
app.post('/api/registrar', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ mensaje: 'Usuario y contraseña son requeridos' });
    }

    //Hashear la contraseña
    const password_hash = await bcrypt.hash(password, 10);

    //Guardar en la base de datos
    await pool.execute(
      'INSERT INTO usuarios (username, password_hash) VALUES (?, ?)',
      [username, password_hash]
    );

    res.status(201).json({ mensaje: 'Usuario registrado exitosamente' });

  } catch (error: any) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ mensaje: 'El nombre de usuario ya existe' });
    }
    console.error('Error en /api/registrar:', error);
    res.status(500).json({ mensaje: 'Error en el servidor' });
  }
});

// LOGUEAR un usuario
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ mensaje: 'Usuario y contraseña son requeridos' });
    }

    const [filas]: any[] = await pool.execute(
      'SELECT * FROM usuarios WHERE username = ?',
      [username]
    );

    if (filas.length === 0) {
      return res.status(404).json({ mensaje: 'Usuario no encontrado' });
    }

    const usuario = filas[0];
    const esPasswordCorrecto = await bcrypt.compare(password, usuario.password_hash);

    if (!esPasswordCorrecto) {
      return res.status(401).json({ mensaje: 'Contraseña incorrecta' });
    }

    //todo está bien, crear un Token JWT
    const token = jwt.sign(
      { 
        id: usuario.id, 
        username: usuario.username 
      },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    //Envia el token al cliente
    res.json({ 
      mensaje: 'Login exitoso', 
      token: token,
      username: usuario.username,
      userId: usuario.id
    });

  } catch (error) {
    console.error('Error en /api/login:', error);
    res.status(500).json({ mensaje: 'Error en el servidor' });
  }
});



// Middleware para proteger rutas API
// El middleware io.use solo protege sockets
const protegerRutaAPI = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ mensaje: 'No hay token, autorización denegada' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    (req as any).usuario = payload;
    next();
  } catch (err) {
    res.status(403).json({ mensaje: 'Token no es válido' });
  }
};


//Endpoint para subir archivos
app.post('/api/upload', protegerRutaAPI, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ mensaje: 'No se subió ningún archivo' });
    }

    // Convertir el buffer a un string base64 para Cloudinary
    const b64 = Buffer.from(req.file.buffer).toString('base64');
    let dataURI = "data:" + req.file.mimetype + ";base64," + b64;
    
    // Subir a Cloudinary
    const resultado = await cloudinary.uploader.upload(dataURI, {
      resource_type: 'auto', // Detecta si es imagen, video.
      folder: 'chat_app' // Carpeta en Cloudinary
    });

    // Devolver la URL segura
    res.json({ url: resultado.secure_url });

  } catch (error) {
    console.error("Error al subir archivo:", error);
    res.status(500).json({ mensaje: 'Error del servidor al subir' });
  }
});

const emitirUsuariosEnSala = async (salaNombre: string) => {
  try {
    
    const socketsEnSala = await io.in(salaNombre).fetchSockets();
    const usuarios = socketsEnSala.map(socket => (socket as any).usuario.username);

    io.to(salaNombre).emit('actualizarListaUsuarios', usuarios);

  } catch (error) {
    console.error("Error al emitir usuarios en sala:", error);
  }
};

// Middleware de Autenticación de Sockets
io.use((socket, next) => {
  const token = socket.handshake.auth.token; 
  if (!token) {
    return next(new Error('Autenticación fallida: No hay token.'));
  }
  try {
    // Verificamos el token con la misma clave secreta
    const payload = jwt.verify(token, JWT_SECRET);
    // para poder usarla en 'io.on('connection')' y en todos los eventos.
    (socket as any).usuario = payload;
    next();
  } catch (err) {
    return next(new Error('Autenticación fallida: Token inválido.'));
  }
});

//Lógica de Socket.io
io.on('connection', (socket) => {
  const usuarioAutenticado = (socket as any).usuario;
  console.log(`Usuario autenticado: ${usuarioAutenticado.username} (ID: ${usuarioAutenticado.id})`);

  socket.on('solicitarMisSalas', async (callback) => {
    try {
      const [filas]: any[] = await pool.execute(
        `SELECT s.id, s.nombre 
         FROM salas s
         JOIN sala_miembros sm ON s.id = sm.sala_id
         WHERE sm.usuario_id = ?`,
        [usuarioAutenticado.id]
      );
      // Enviamos las salas al cliente
      callback(filas); 
    } catch (error) {
      console.error("Error en solicitarMisSalas:", error);
      callback([]); // Devuelve array vacío en caso de error
    }
  });

  socket.on('solicitarSalasPublicas', async (callback) => {
    try {
      const [filas]: any[] = await pool.execute(
        'SELECT id, nombre FROM salas' // Por ahora, todas las salas son públicas
      );
      callback(filas);
    } catch (error) {
      console.error("Error en solicitarSalasPublicas:", error);
      callback([]);
    }
  });

  // Escuchar evento de "unirse" 
  // Ahora también recibimos la 'sala'
  socket.on('unirseASala', async (salaNombre: string, callback) => {
    try {
      //Encontrar o Crear la Sala en la DB
      let [filasSalas]: any[] = await pool.execute(
        'SELECT id FROM salas WHERE nombre = ?', [salaNombre]
      );
      
      let salaId: number;
      if (filasSalas.length === 0) {
        const [resultInsert]: any = await pool.execute(
          'INSERT INTO salas (nombre) VALUES (?)', [salaNombre]
        );
        salaId = resultInsert.insertId;
      } else {
        salaId = filasSalas[0].id;
      }

      //Crear la membresía (la "memoria" del usuario)
      await pool.execute(
        'INSERT IGNORE INTO sala_miembros (usuario_id, sala_id) VALUES (?, ?)',
        [usuarioAutenticado.id, salaId]
      );
      socket.join(salaNombre);
      socket.to(salaNombre).emit('notificacion', `${usuarioAutenticado.username} se ha unido a la sala.`);

      // Guardar la info de la sala en el socket para uso futuro
      (socket as any).salaInfo = { id: salaId, nombre: salaNombre };

      // Devolver la info de la sala al cliente
      callback({ id: salaId, nombre: salaNombre });
      emitirUsuariosEnSala(salaNombre);

    } catch (error) {
      console.error("Error en unirseASala:", error);
    }
  });

  socket.on('solicitarHistorial', async (salaId: number, callback) => {
    try {
      const [filas]: any[] = await pool.execute(
        `SELECT m.contenido, m.fecha_creacion, u.username 
         FROM mensajes m
         JOIN usuarios u ON m.usuario_id = u.id
         WHERE m.sala_id = ?
         ORDER BY m.fecha_creacion ASC
         LIMIT 50`,
        [salaId]
      );

      // Mapeamos los nombres de columna de la DB a nuestro Payload
      const historial = filas.map((fila : any) => ({
        usuario: fila.username,
        texto: fila.contenido,
        timestamp: fila.fecha_creacion
      }));
      
      callback(historial); // Enviamos el historial de vuelta

    } catch (error) {
      console.error("Error en solicitarHistorial:", error);
      callback([]);
    }
  });

  socket.on('sendMessage', async (payload: { texto?: string, imagen_url?: string }) => {
  try {
    const { id: usuarioId, username } = (socket as any).usuario;
    const infoSala = (socket as any).salaInfo;
    if (!infoSala) {
      console.warn(`Usuario ${username} intentó enviar mensaje sin estar en una sala.`);
      return; 
    }
    const { id: salaId, nombre: salaNombre } = infoSala;
    const { texto, imagen_url } = payload;

    // 1. Guardar en la Base de Datos
    await pool.execute(
      'INSERT INTO mensajes (contenido, imagen_url, usuario_id, sala_id) VALUES (?, ?, ?, ?)',
      [texto || null, imagen_url || null, usuarioId, salaId]
    );

    // 2. Crear el payload para transmitir
    const payloadCompleto = {
      usuario: username,
      texto: texto || null,
      imagen_url: imagen_url || null,
      timestamp: new Date().toISOString()
    };
    
    // 3. Transmitir a todos en la sala
    io.to(salaNombre).emit('receiveMessage', payloadCompleto);

  } catch (error) {
    console.error("Error en sendMessage:", error);
  }
});

  socket.on('escribiendo', () => {
    try {
      const { username } = (socket as any).usuario;
      const infoSala = (socket as any).salaInfo;
      if (!infoSala) {
        return; 
      }
      const { nombre: salaNombre } = infoSala;
      socket.to(salaNombre).emit('alguienEscribe', username);
    } catch (error) {
    }
  });

  const handleDesconexion = () => {
    try {
      const { id: usuarioId, username } = (socket as any).usuario;
      const infoSala = (socket as any).salaInfo;
      if (!infoSala) {
        // El usuario se desconectó del lobby, no pasa nada.
        return; 
      }
      const { nombre: salaNombre } = infoSala;
      if (salaNombre) {
        socket.to(salaNombre).emit('notificacion', `${username} ha abandonado la sala.`);
        socket.leave(salaNombre);
        emitirUsuariosEnSala(salaNombre);
        console.log(`Usuario ${username} abandonó la sala ${salaNombre}`);
      }
    } catch (error) {
    }
  };

  socket.on('dejarSala', handleDesconexion);
  socket.on('disconnect', handleDesconexion);
});

// Ruta de prueba de Express
app.get('/', (req, res) => {
  res.send('<h1>Servidor de Chat Corriendo</h1>');
});

// --- Iniciar el Servidor ---
servidor.listen(PORT, () => {
  console.log(`Servidor en http://localhost:${PORT}`);
});