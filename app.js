const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const csv = require('csv-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
var bodyParser = require('body-parser')
const iconv = require('iconv-lite');
const fs = require('fs');
const ejs = require('ejs')
const stream = require('stream');
const path = require('path')
const port = 3000;

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
require('dotenv').config()
const jwtSecret = "klsgj_àç465_!?"
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.set('views', path.join(__dirname, 'views'));
app.use('/upload', express.static(path.join(__dirname, 'upload')));


// Middleware pour parser les requêtes JSON entrantes
//app.use(jsonParser);
app.use(cors({
    origin: "http://127.0.0.1:3000",
    methods: "GET,POST,PUT,DELETE",
    allowedHeaders: 'Content-Type,Authorization'
}));

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', 'http://127.0.0.1:3000');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content, Accept, Content-Type, Authorization');
    res.setHeader('Acces-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    next();
});



const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'upload/')
    },
    filename: function(req, file, cb) {
        let name = file.originalname.split(' ').join('_');
        cb(null, name.split(file.mimetype)[0] + Date.now() + '.pdf')
    }
});

const uploadPDF = multer({ storage: storage });
// Configuration de Multer pour le stockage en mémoire
const upload = multer({ storage: multer.memoryStorage() });

app.post('/api/updatetnd/:id/', (req, res) => {
    console.log(req.body)
    const id = req.params.id;
    const amount = req.body.amount
    const sql = `UPDATE transactions SET montant_tnd= ? WHERE id=?`;
    db.run(sql, [parseFloat(amount), parseInt(id)], function(err) {
        if (err) {
            return res.status(500).send({ message: "Erreur lors de la mise à jour de la base de données", error: err.message });
        }
        res.send({ message: "Fichier téléchargé et transaction mise à jour.", amount: amount });
    });

})

app.post('/api/updatecom/:id/', (req, res) => {
    console.log(req.body)
    const id = req.params.id;
    const commentaire = req.body.commentaire
    const sql = `UPDATE transactions SET commentaire= ? WHERE id=?`;
    db.run(sql, [commentaire, parseInt(id)], function(err) {
        if (err) {
            return res.status(500).send({ message: "Erreur lors de la mise à jour de la base de données", error: err.message });
        }
        res.send({ message: "Fichier téléchargé et transaction mise à jour.", commentaire: commentaire });
    });

})

app.put('/api/update/state/:id/', (req, res) => {
    console.log(req.body)
    const id = req.params.id;
    const state = req.body.state
    const sql = `UPDATE transactions SET etat= ? WHERE id=?`;
    db.run(sql, [state, parseInt(id)], function(err) {
        if (err) {
            return res.status(500).send({ message: "Erreur lors de la mise à jour de la base de données", error: err.message });
        }
        res.send({ message: "Etat mis à jour.", state: state });
    });

})



app.put('/api/delete/pdf/:id',express.static(path.join(__dirname, '/upload')), (req, res) => {
    const id = req.params.id;
    const file_path = req.body.file_path
    const sql = `UPDATE transactions SET file_path=null WHERE id=?`;
    if (file_path) {
        fs.unlink(file_path, () => {
            
            db.run(sql, [parseInt(id)], function(err) {
                if (err) {
                    return res.status(500).send({ message: "Erreur dans la supression", error: err.message });
                }
                res.status(200).send({ message: "Element supprimer avec succees"});
            });
        })   
    }

})



app.delete('/api/delete/trans/:id',express.static(path.join(__dirname, '/upload')), (req, res) => {
    const id = req.params.id;
    const file_path = req.body.file_path
    const sql = `DELETE FROM transactions WHERE id=?`;
    console.log(path.join(__dirname, '/upload'))
    if (file_path) {
        fs.unlink(file_path, () => {
            
            db.run(sql, [parseInt(id)], function(err) {
                if (err) {
                    return res.status(500).send({ message: "Erreur dans la supression", error: err.message });
                }
                res.status(200).send({ message: "Element supprimer avec succees"});
            });
        })   
    }
    else {
        db.run(sql, [parseInt(id)], function(err) {
            if (err) {
                return res.status(500).send({ message: "Erreur dans la supression", error: err.message });
            }
            res.status(200).send({ message: "Element supprimer avec succees"});
        });
        }


})

app.post('/api/upload/pdf/:id', uploadPDF.single('file'), (req, res) => {
    const id = req.params.id;
    const file_path = req.file.path
    console.log(file_path, id)
        // Mise à jour de la base de données avec le chemin du fichier
    const sql = `UPDATE transactions SET file_path= ? WHERE id=?`;
    db.run(sql, [file_path, parseInt(id)], function(err) {
        if (err) {
            return res.status(500).send({ message: "Erreur lors de la mise à jour de la base de données", error: err.message });
        }
        console.log('HELLO', file_path, id)
        res.send({ message: "Fichier téléchargé et transaction mise à jour.", filePath: file_path });
    });

});
let db = new sqlite3.Database('gestion_bancaire.db', sqlite3.OPEN_READWRITE, (err) => {
    if (err) {
        console.log('ERROR', err.message);
    } else {
        console.log('Connected to the SQLite database.');
    }
});

app.post('/api/upload/csv', upload.single('csvfile'), (req, res) => {
    if (!req.file) {
        return res.status(400).send({ message: "No file provided" });
    }

    const decodedContent = iconv.decode(req.file.buffer, 'UTF-16');

    const bufferStream = new stream.PassThrough();
    bufferStream.end(decodedContent);
    //db.run('DELETE FROM transactions')

    const results = [];

    bufferStream
        .pipe(csv({ separator: '\t', headers: ['date', 'description', 'date_value', 'debit', 'credit', 'solde'] }))
        .on('data', (data) => {

            
            data.debit = data.debit ? parseFloat(data.debit.replace(' ','').replace(',', '.')) : null;
            data.credit = data.credit ? parseFloat(data.credit.replace(' ','').replace(',', '.')) : null;
            data.solde = data.solde ? parseFloat(data.solde.replace(' ','').replace(',', '.')) : null;
            if (!data.date?.includes('Date')) {
                results.push(data);
            }

        })
        .on('end', () => {
            console.log('CSV parsing completed.');
            handleInserts(results, res);
        });
});

app.post('/api/signup', (req,res) => {
    bcrypt.hash(req.body.password, 10).then((hash) => {
        db.run('INSERT INTO users(username,password,role) VALUES(?, ?, ?)', [req.body.email, hash, 'User'], (err) => {

            if(err){
            console.log('ERROR');
        }
            console.log(`USER ADDED ${req.body.email}`)
		res.render('login');
    }); 

    });

});


//app.post('/api/login', async(req,res) =>{

//})

app.post('/api/login', async (req, res) => {

    const { username, password } = req.body;

    // Requête SQL pour récupérer le mot de passe haché de l'utilisateur
    const sql = `SELECT password FROM users WHERE username = ?`;

    db.get(sql, [username], async (err, row) => {

        if (err) {
            console.error('Erreur lors de l\'exécution de la requête SQL :', err.message);
            res.status(500).send('Erreur du serveur.');
        } else if (row) {
            //console.log("req", username, password, row)
            // Comparaison du mot de passe haché avec le mot de passe fourni
            const passwordMatch = await bcrypt.compare(password, row.password);
            if (passwordMatch) {
                //res.sendFile('../public/index.html')
                res.status(201).json({
                    token: jwt.sign({username}, jwtSecret, {
                      algorithm: "HS256",
                    }),
                  })
                //res.status(200).send('Authentification réussie.');
            } else {
                console.log('here ?')
                res.status(401).send('Nom d\'utilisateur ou mot de passe incorrect.');
            }
        } else {
            res.status(401).send('Nom d\'utilisateur ou mot de passe incorrect.');
        }
    });
});



function handleInserts(data, res) {
    const insertData = data.filter((item) => item.date && item.description);

    db.serialize(() => {
        const insertStmt = db.prepare('INSERT INTO transactions (date, description, debit, credit, solde) VALUES (?, ?, ?, ?, ?)');
        insertData.forEach((row) => {
            //console.log(row,"solde",row.solde)
            insertStmt.run([row.date, row.description, row.debit, row.credit, row.solde], function(err) {
                if (err) {
                    console.error('Error inserting data:', err.message);
                }
            });
        });
        insertStmt.finalize();
        res.status(201).send({ message: 'All data has been inserted successfully.', rowCount: insertData.length });
    });
}

// Autres parties du code inchangées...

const pdfUpload = multer({ storage: multer.memoryStorage() });

app.post('/api/upload/pdf', pdfUpload.single('pdfFile'), (req, res) => {
    if (!req.file) {
        return res.status(400).send({ message: "Aucun fichier fourni" });
    }

    // Enregistrer le fichier PDF dans un répertoire temporaire ou un service de stockage comme Amazon S3
    // Récupérer le chemin du fichier et l'associer à la transaction dans la base de données
    const filePath = 'upload/' + req.file.originalname;

    // Enregistrement du chemin du fichier dans la base de données
    db.run('UPDATE transactions SET file_path = ? WHERE id = ?', [filePath, req.body.transactionId], (err) => {
        if (err) {
            console.error('Erreur lors de la mise à jour du chemin du fichier dans la base de données:', err.message);
            return res.status(500).send({ message: 'Erreur lors de la mise à jour du chemin du fichier dans la base de données.' });
        }
        res.status(200).send({ message: 'Chemin du fichier enregistré avec succès.' });
    });
});


// Endpoint pour récupérer les transactions de la base de données

// app.get('/api/transactions', (req, res) => {
//     db.all(`SELECT  *  FROM transactions;`, [], (err, rows) => {
//         if (err) {
//             console.error('Error fetching transactions:', err.message);
//             return res.status(500).send('Error fetching transactions from the database.');
//         }
//         res.json(rows);
//     });
// });


function authenticateToken(req, res, next) {
    
    const token = req.query.token
    
    if (token == null) return res.redirect('/login');
    
    jwt.verify(token, jwtSecret, (err, user) => {
        
        if (err) return res.redirect('/login');
        req.user = user; // attach the user payload to req
        next();
    });
}
app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.render('login');
});


app.get('/api/transactions', authenticateToken, (req, res) => {
    console.log("req me .", req)
    db.all(`SELECT * FROM transactions ORDER BY SUBSTR(date, 7, 4) || '-' || SUBSTR(date, 4, 2) || '-' || SUBSTR(date, 1, 2) DESC;`, [], (err, rows) => {
        if (err) {
            console.error('Error fetching transactions:', err.message);
            return res.status(500).send('Error fetching transactions from the database.');
        }
        console.log('rows', rows)
        res.status(200).json(rows);
    });


});

app.get('/index', authenticateToken, (req, res) => {
    const formatNumberTnd = function (value) {
        return value ? parseFloat(value).toLocaleString('fr-FR', { style: 'currency', currency: 'TND', minimumFractionDigits: 2 }) : '';
    }
    db.all(`SELECT * FROM transactions ORDER BY SUBSTR(date, 7, 4) || '-' || SUBSTR(date, 4, 2) || '-' || SUBSTR(date, 1, 2) DESC;`, [], (err, rows) => {
        if (err) {
            console.error('Error fetching transactions:', err.message);
            return res.status(500).send('Error fetching transactions from the database.');
        }
        console.log('rows', rows)
        res.render('index', {transactions : rows, formatNumberTnd: formatNumberTnd});
        //res.status(200).json(rows);
    });
    
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
