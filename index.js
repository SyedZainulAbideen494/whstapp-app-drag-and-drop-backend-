const express = require("express");
const mysql = require("mysql2");
const app = express();
const bodyParser = require("body-parser");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const nodemailer = require('nodemailer');
const uuid = require('uuid');
const cron = require('node-cron');
const PORT = process.env.PORT || 8080;
const axios = require('axios');
const stripe = require('stripe')('sk_test_51LoS3iSGyKMMAZwstPlmLCEi1eBUy7MsjYxiKsD1lT31LQwvPZYPvqCdfgH9xl8KgeJoVn6EVPMgnMRsFInhnnnb00WhKhMOq7');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const QRCode = require('qrcode');
const fs = require('fs');

// URL Constants
const BASE_URL = 'https://f9ac-122-172-85-46.ngrok-free.app';
const SUCCESS_URL = `${BASE_URL}/success?session_id={CHECKOUT_SESSION_ID}&sender_id=`;
const CANCEL_URL = `${BASE_URL}/cancel`;
const TICKET_URL = `${BASE_URL}/tickets/`;
const DOCUMENT_URL = `${BASE_URL}/documents/`;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.use(session({
  key: "userId",
  secret: "Englishps4",
  resave: false,
  saveUninitialized: false,
  cookie: {
    expires: 60 * 60 * 24 * 12,
  },
}));

app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "DELETE", "PUT"],
  credentials: true,
}));

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

const connection = mysql.createPool({
  connectionLimit: 10, // Maximum number of connections in the pool
  host: "localhost",
  user: "root",
  password: "Englishps#4",
  database: "whatsapp",
});

connection.getConnection((err) => {
  if (err) {
    console.error("Error connecting to MySQL database: ", err);
  } else {
    console.log("Connected to MySQL database");
  }
});

const userStates = {};

app.post('/webhook/:app_id', (req, res) => {
  console.log('Incoming POST request:', JSON.stringify(req.body, null, 2)); // Log incoming POST request payload

  try {
    if (req.body && req.body.entry && req.body.entry[0].changes && req.body.entry[0].changes[0].value.messages) {
      const message = req.body.entry[0].changes[0].value.messages[0];
      const senderId = message.from; // Assuming sender ID is provided in the request
      const messageType = message.type;

      if (messageType === 'text' || messageType === 'button') {
        const messageBody = messageType === 'text' ? message.text.body.toLowerCase() : message.button.payload.toLowerCase();

        if (!userStates[senderId]) {
          userStates[senderId] = { step: 0, data: {} };
        }

        if (messageBody === 'hi') {
          sendWhatsAppMessage({
            messaging_product: "whatsapp",
            to: senderId,
            type: "template",
            template: {
              name: "pg_temp_1", // Corrected template name
              language: { code: "en_US" }
            }
          });
        } else {
          sendWhatsAppMessage({
            messaging_product: "whatsapp",
            to: senderId,
            type: "text",
            text: {
              body: "Sorry, I didn't understand that. Please type 'hi' for assistance."
            }
          });
        }
      }
    }

    res.sendStatus(200); // Respond to the webhook POST request
  } catch (error) {
    console.error('Error processing the webhook:', error);
    res.sendStatus(500); // Internal Server Error
  }
});



// Function to send WhatsApp message
function sendWhatsAppMessage(data) {
  const config = {
    headers: {
      'Authorization': 'Bearer EAAFsUoRPg1QBO197JBrZB7lmmFHAH6wHds1qOhDd8asVgk2MKnegr6WgipctTFtWrabHManZBcxi7y0vNZCqxzuy3GoL31lcWZB0LcQN7cGlXDrZBksvO3ZBYi8jQcwmHWPyS36OElP2GyLPoU83ljXnNsP6yFPawRy3n09tgOYQ6s1IjOQXKGk7iKffLfdXfN',
      'Content-Type': 'application/json'
    }
  };

  axios.post('https://graph.facebook.com/v19.0/332700683252247/messages', data, config)
    .then(response => {
      console.log('Message sent successfully:', response.data);
    })
    .catch(error => {
      console.error('Error sending message:', error.response.data);
    });
}

// Webhook verification endpoint (GET request)
app.get('/webhook', (req, res) => {
  const VERIFY_TOKEN = "EAAFsUoRPg1QBO197JBrZB7lmmFHAH6wHds1qOhDd8asVgk2MKnegr6WgipctTFtWrabHManZBcxi7y0vNZCqxzuy3GoL31lcWZB0LcQN7cGlXDrZBksvO3ZBYi8jQcwmHWPyS36OElP2GyLPoU83ljXnNsP6yFPawRy3n09tgOYQ6s1IjOQXKGk7iKffLfdXfN"; // Replace with your verification token
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('Webhook verified!');
    res.status(200).send(challenge);
  } else {
    console.error('Failed verification. Make sure the verification tokens match.');
    res.sendStatus(403);
  }
});

// GET endpoint for testing
app.get('/', (req, res) => {
  res.send('Welcome to the Facebook Messenger webhook!');
});

// Success endpoint to handle successful payments
app.get('/success', async (req, res) => {
  const sessionId = req.query.session_id;
  const senderId = req.query.sender_id;
  if (!sessionId || !senderId) {
    return res.status(400).send('Missing session_id or sender_id');
  }
  try {
    await handlePaymentSuccess(sessionId, senderId);
    res.send('Payment successful! Your recipt has been sent to your WhatsApp.');
  } catch (error) {
    console.error('Error handling payment success:', error);
    res.status(500).send('An error occurred while processing your payment.');
  }
});

/*app code*/
app.post('/addUser', (req, res) => {
  const {
    email,
    password,
    name,
  } = req.body;

 
  const randomString = uuid.v4().replace(/-/g, '').substr(0, 8);

  // Check if the email already exists in the database
  const checkEmailQuery = 'SELECT * FROM users WHERE email = ?';
  connection.query(checkEmailQuery, [email], (err, results) => {
    if (err) {
      console.error('Error checking email:', err);
      res.status(500).json({ error: 'Internal server error' });
    } else if (results.length > 0) {
      // If email already exists, return a message
      res.status(409).json({ error: 'User with this email already exists' });
    } else {
      // If email doesn't exist, proceed with user registration
      bcrypt.hash(password, saltRounds, (hashErr, hash) => {
        if (hashErr) {
          console.error('Error hashing password: ', hashErr);
          res.status(500).json({ error: 'Internal server error' });
        } else {
          const insertQuery =
            'INSERT INTO users (email, password, user_name) VALUES (?, ?, ?)';
          const values = [
            email,
            hash,
            name
          ];

          connection.query(insertQuery, values, (insertErr, insertResults) => {
            if (insertErr) {
              console.error('Error inserting user: ', insertErr);
              res.status(500).json({ error: 'Internal server error' });
            } else {
              console.log('User registration successful!');
              res.sendStatus(200);
            }
          });
        }
      });
    }
  });
});

const verifyjwt = (req, res) => {
  const token = req.headers["x-access-token"];

  if (!token) {
    res.send("no token unsuccessfull");
  } else {
    jwt.verify(token, "jwtsecret", (err, decoded) => {
      if (err) {
        res.json({ auth: false, message: "u have failed to auth" });
      } else {
        req.user_id = decoded.id;
      }
    });
  }
};

app.get("/userAuth", verifyjwt, (req, res) => {});

app.get("/login", (req, res) => {
  if (req.session.user) {
    res.send({ loggedIn: true, user: req.session.user });
  } else {
    res.send({ loggedIn: false });
  }
});

app.post("/login", (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  connection.query(
    "SELECT * FROM users WHERE email = ?",
    email,
    (err, result) => {
      if (err) {
        res.send({ err: err });
      }
      if (result.length > 0) {
        bcrypt.compare(password, result[0].password, (error, response) => {
          if (response) {
            const id = result[0].id;
            const token = jwt.sign({ id }, "jwtsecret", {
              expiresIn: 86400,
            });

            connection.query(
              `update users set jwt = "${token}" where email = "${email}" `,
              (err, result) => {
                if (err) console.log(err);
                console.log(result);
              }
            );
            req.session.user = result;
            res.json({ auth: true, token: token, result: result });
          } else {
            res.json({ auth: false, message: "Email or password is wrong" });
          }
        });
      } else {
        res.json({ auth: false, message: "User does not exist" });
      }
    }
  );
});


app.post('/create/app', async (req, res) => {
  const { appId, token, localStorageToken } = req.body;

  if (!appId || !token || !localStorageToken) {
    return res.status(400).json({ error: 'App ID, Token, and Local Storage Token are required' });
  }

  try {
    // Verify the app exists using the Facebook API
    const response = await axios.get(`https://graph.facebook.com/v19.0/${appId}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    const appName = response.data.name;

    // Fetch user information based on localStorageToken
    const userSql = 'SELECT user_id FROM users WHERE jwt = ?';
    connection.query(userSql, [localStorageToken], (err, results) => {
      if (err) {
        console.error('Error fetching user from database:', err);
        return res.status(500).json({ error: 'Error fetching user from database' });
      }

      if (results.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      const userId = results[0].user_id;

      // Insert the app details into the database, including the webhook URL
      const webhookUrl = `${BASE_URL}/webhook/${appId}`;
      const insertAppSql = 'INSERT INTO apps (app_id, app_name, token, user_id, webhook) VALUES (?, ?, ?, ?, ?)';
      connection.query(insertAppSql, [appId, appName, token, userId, webhookUrl], (err, result) => {
        if (err) {
          console.error('Error inserting app into database:', err);
          return res.status(500).json({ error: 'Error inserting app into database' });
        }
        console.log('App inserted into database');
        res.json({ message: 'App and webhook inserted successfully' });
      });
    });
  } catch (error) {
    console.error('Error checking app existence:', error.response?.data || error.message);
    if (error.response && error.response.status === 404) {
      return res.status(404).json({ error: 'App does not exist' });
    }
    return res.status(500).json({ error: 'Error checking app existence' });
  }
});

app.post('/user-apps', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'Token is required' });
  }

  // Fetch user_id using the provided token
  const userSql = 'SELECT user_id FROM users WHERE jwt = ?';
  connection.query(userSql, [token], (err, results) => {
    if (err) {
      console.error('Error fetching user from database:', err);
      return res.status(500).json({ error: 'Error fetching user from database' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userId = results[0].user_id;

    // Fetch all apps associated with the user_id
    const appsSql = 'SELECT * FROM apps WHERE user_id = ?';
    connection.query(appsSql, [userId], (err, results) => {
      if (err) {
        console.error('Error fetching apps from database:', err);
        return res.status(500).json({ error: 'Error fetching apps from database' });
      }

      res.json({ apps: results });
    });
  });
});

app.get('/apps/:appId', (req, res) => {
  const { appId } = req.params;

  const sql = 'SELECT * FROM apps WHERE app_id = ?';
  connection.query(sql, [appId], (err, result) => {
      if (err) {
          console.error('Error fetching app details:', err);
          return res.status(500).json({ error: 'Error fetching app details' });
      }

      if (result.length === 0) {
          return res.status(404).json({ error: 'App not found' });
      }

      res.json(result[0]);
  });
});


app.get('/webhook/:app_id', (req, res) => {
  const app_id = req.params.app_id;

  // Query the database to get the VERIFY_TOKEN for the given app_id
  connection.query('SELECT token FROM apps WHERE app_id = ?', [app_id], (err, results) => {
    if (err) {
      console.error('Error fetching VERIFY_TOKEN from database:', err);
      return res.status(500).json({ error: 'Error fetching VERIFY_TOKEN from database' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'App not found' });
    }

    const VERIFY_TOKEN = results[0].token;

    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
      console.log('Webhook verified!');
      res.status(200).send(challenge);
    } else {
      console.error('Failed verification. Make sure the verification tokens match.');
      res.status(403).json({ error: 'Failed verification. Make sure the verification tokens match.' });
    }
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});