// Import required modules
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Initialize Express app and HTTP server
const app = express();
const server = http.createServer(app);
const io = socketIo(server); // Initialize Socket.io for real-time communication


const multer = require('multer');
const path = require('path');
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
      cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
      cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// Secret for JWT signing and verification
const secret = 'your-secret-key-12345'; // Use a strong, random secret in production

// Middleware to parse JSON request bodies
app.use(express.json());

// Serve static files from the "public" folder
app.use(express.static('public'));

// Connect to MongoDB
mongoose.connect('mongodb://localhost/whatsapp-clone')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define User and Message models using Mongoose
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true }
});


const groupSchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true }, // Unique group name
  members: [{ type: String }] // List of usernames in the group
});

const Group = mongoose.model('Group', groupSchema);

// Hash password before saving the user
userSchema.pre('save', function(next) {
  const user = this;
  if (!user.isModified('password')) return next();
  bcrypt.hash(user.password, 10, (err, hash) => {
    if (err) return next(err);
    user.password = hash;
    next();
  });
});

// Compare password during login
userSchema.methods.comparePassword = function(password, callback) {
  bcrypt.compare(password, this.password, (err, isMatch) => {
    if (err) return callback(err);
    callback(null, isMatch);
  });
};

const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  receiver: { type: String, required: true },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', messageSchema);

// JWT middleware for authentication
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).send('Access denied');
  jwt.verify(token, secret, (err, user) => {
    if (err) return res.status(403).send('Invalid token');
    req.user = user;
    next();
  });
}


app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.post('/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) {
      return res.status(400).send('No file uploaded.');
  }
  // Return the file URL so the front-end can use it in the chat
  res.json({ fileUrl: `/uploads/${req.file.filename}` });
});

// User registration route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const newUser = new User({ username, password });
    await newUser.save();
    res.send('User registered successfully');
  } catch (err) {
    res.status(400).send('Error registering user');
  }
});
app.post('/groups', authenticateToken, async (req, res) => {
  const { groupName, members } = req.body;

  try {
      // Ensure the group name is unique
      const existingGroup = await Group.findOne({ name: groupName });
      if (existingGroup) {
          return res.status(400).send('Group name already exists');
      }

      // Create the group with the members
      const newGroup = new Group({ name: groupName, members });
      await newGroup.save();

      res.status(201).json({ message: 'Group created successfully', group: newGroup });
  } catch (err) {
      res.status(500).send('Error creating group');
  }
});
app.get('/groups/:groupName/members', authenticateToken, async (req, res) => {
  const { groupName } = req.params;

  try {
      // Find the group by name
      const group = await Group.findOne({ name: groupName });
      if (!group) {
          return res.status(404).json({ message: 'Group not found' });
      }

      // Return the list of members
      res.json({ members: group.members });
  } catch (err) {
      res.status(500).json({ message: 'Error retrieving group members' });
  }
});
app.get('/groups', authenticateToken, async (req, res) => {
  try {
      const groups = await Group.find();
      res.json(groups);
  } catch (err) {
      res.status(500).send('Error fetching groups');
  }
});
app.post('/groups/:groupName/messages', authenticateToken, async (req, res) => {
  const { groupName } = req.params;
  const { content, fileUrl } = req.body;

  try {
      // Check if the group exists
      const group = await Group.findOne({ name: groupName });
      if (!group) {
          return res.status(404).send('Group not found');
      }

      // Emit the message to all group members via Socket.io
      group.members.forEach(member => {
          const message = { sender: req.user.username, content, fileUrl };
          const recipientSocket = Array.from(io.sockets.sockets).find(([id, s]) => s.username === member);
          if (recipientSocket) {
              recipientSocket[1].emit('group message', { group: groupName, message });
          }
      });

      res.status(200).send('Message sent to group');
  } catch (err) {
      res.status(500).send('Error sending group message');
  }
});

// User login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).send('User not found');
    user.comparePassword(password, (err, isMatch) => {
      if (!isMatch) return res.status(400).send('Invalid credentials');
      const token = jwt.sign({ username: user.username }, secret);
      res.send({ token });
    });
  } catch (err) {
    res.status(500).send('Server error');
  }
});


app.get('/users', authenticateToken, async (req, res) => {
  try {
      const users = await User.find({ username: { $ne: req.user.username } });
      res.json(users.map(user => user.username)); // Return only usernames
  } catch (err) {
      res.status(500).send('Error fetching users');
  }
});
// Get chat message history between two users
app.get('/messages', authenticateToken, async (req, res) => {
  const { to } = req.query;
  try {
    const messages = await Message.find({
      $or: [
        { sender: req.user.username, receiver: to },
        { sender: to, receiver: req.user.username }
      ]
    }).sort('timestamp');
    res.send(messages);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// WebSocket: Handle real-time messaging using Socket.io
io.use((socket, next) => {
  const token = socket.handshake.query.token;
  if (!token) return next(new Error('Authentication error'));
  jwt.verify(token, secret, (err, decoded) => {
    if (err) return next(new Error('Invalid token'));
    socket.username = decoded.username; // Add username to the socket connection
    next();
  });
});

io.on('connection', (socket) => {
  console.log(`${socket.username} connected`);
  socket.on('set username', (username) => {
    socket.username = username;
    console.log(`${username} is connected`);
});
socket.on('send message', async (data) => {
  const { recipient, content, fileUrl } = data;

  // If the message is to a group
  if (recipient.startsWith('Group:')) {
      const groupName = recipient.replace('Group: ', '');
      
      // Find the group members
      const group = await Group.findOne({ name: groupName });
      if (group) {
          // Broadcast the message to all group members except the sender
          group.members.forEach(member => {
              if (member !== socket.username) { // Don't send to the sender
                  const memberSocket = findSocketByUsername(member);
                  if (memberSocket) {
                      console.log(`Sending message to group member: ${member}`);
                      memberSocket.emit('group message', {
                          groupName,
                          sender: socket.username,
                          content,
                          fileUrl
                      });
                  }
              }
          });
      }
  } else {
      // If it's a private message, send it to the individual user
      const recipientSocket = findSocketByUsername(recipient);
      if (recipientSocket) {
          recipientSocket.emit('private message', {
              sender: socket.username,
              content,
              fileUrl
          });
      }
  }
});
  // Handle private messaging
  socket.on('private message', (data) => {
    const { to, content } = data;
    const message = { sender: socket.username, receiver: to, content };

    // Save message to the database
    const newMessage = new Message(message);
    newMessage.save().then(() => {
      // Send the message to the recipient
      const recipientSocket = Array.from(io.sockets.sockets).find(([id, s]) => s.username === to);
      if (recipientSocket) {
          // Send the message to the recipient
          recipientSocket[1].emit('private message', message);
      }
      io.to(to).emit('private message', message);
    });
    socket.on('set username', (username) => {
      socket.username = username;
  });
  socket.on('send message', async (data) => {
    const { recipient, content, fileUrl } = data;

    // Check if the recipient is a group
    if (recipient.startsWith('Group:')) {
        const groupName = recipient.replace('Group: ', '');

        // Find the group members from the database
        const group = await Group.findOne({ name: groupName });
        if (group) {
            // Broadcast the message to all group members except the sender
            group.members.forEach(member => {
                if (member !== socket.username) { // Skip the sender
                    const memberSocket = findSocketByUsername(member);
                    if (memberSocket) {
                        memberSocket.emit('group message', {
                            groupName,
                            sender: socket.username,
                            content,
                            fileUrl
                        });
                    }
                }
            });
        }
    } else {
        // If it's a private message, send it to the recipient
        const recipientSocket = findSocketByUsername(recipient);
        if (recipientSocket) {
            recipientSocket.emit('private message', {
                sender: socket.username,
                content,
                fileUrl
            });
        }
    }
});
  });


  socket.on('disconnect', () => {
    console.log(`${socket.username} disconnected`);
  });
});
function findSocketByUsername(username) {
  return Array.from(io.sockets.sockets.values()).find(socket => socket.username === username);
}
// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
