const express = require('express');
const bodyParser = require('body-parser');
const { check, validationResult } = require('express-validator');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const dbUrl = process.env.DATABASE_URL;
// const dbUrl = `mongodb+srv://Alawode-Toheeb:<Tosibey2>@atlascluster.obnjjfm.mongodb.net/`;
const jwtSecret = process.env.JWT_SECRET;

// Middleware
app.use(bodyParser.json());


// Connecting to MongoDB
const mongoDb_url = mongoose
  .connect(
    dbUrl
  )
  .then(() => console.log("connected to the database"))
  .catch((error) => console.log(error));

console.log(mongoDb_url);

const Transaction = mongoose.model('Transaction', {
    amount: Number,
    destinationWallet: String,
    agentId: String,
    pin: String,
  });
  

// Rate limiting middleware
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
});
app.use('/api/', apiLimiter);

// Middleware function to verify JWT token
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(401).json({ message: 'Authorization token is missing' });
  }

  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.agentId = decoded.agentId; // Store agent ID 
    next();
  });
}

// agent authentication logic
function authenticateAgent(agentId, pin) {
  const validAgents = [
    { agentId: 'agent123', pinHash: 'hashedPIN123' }, 
    
  ];

  const agent = validAgents.find((a) => a.agentId === agentId);
  if (!agent) {
    return false; // Agent not found
  }

  const pinMatches = bcrypt.compareSync(pin, agent.pinHash);
  if (!pinMatches) {
    return false; // Invalid PIN
  }

  return true; // Agent authenticated successfully
}

// Create a new transaction
app.post(
  '/api/transactions',
  [
    check('amount').isNumeric(),
    check('destinationWallet').isLength({ min: 12, max: 12 }),
    check('agentId').isLength({ min: 12, max: 12 }),
    check('pin').isLength({ min: 4, max: 4 }),
  ],
  verifyToken,
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount, destinationWallet, agentId, pin } = req.body;

    // Authenticate agent
    if (!authenticateAgent(agentId, pin)) {
      return res.status(401).json({ message: 'Agent authentication failed' });
    }

    // Hash and salt the PIN for secure storage
    const hashedPin = bcrypt.hashSync(pin, 10);

    // Creating a new transaction
    const transaction = new Transaction({
      amount,
      destinationWallet,
      agentId,
      pin: hashedPin,
    });


    async function updateAccountBalances(transaction) {
        return {
            account1Balance: 1000, // Updated balance for account 1
            account2Balance: 2000, // Updated balance for account 2
          };
        };

        async function logTransactionToAuditLog(transaction) {
            return 'Transaction logged to audit log successfully';
        };

    transaction.save(async (err)  => {
      if (err) {
        console.error('Error creating transaction:', err);
        return res.status(500).json({ error: 'Error creating transaction' });
      }

      // Update for  account balances 
      const updatedBalances = await updateAccountBalances(transaction);

      // audit log here
      const logTransaction = await logTransactionToAuditLog(transaction);

      return res.status(201).json({ message: `${updatedBalances} && ${logTransaction} Transaction created successfully` });
    });
  }
);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
