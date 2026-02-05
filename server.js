const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'addzy-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Create uploads directory
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// MongoDB Connection - FIXED (removed deprecated options)
mongoose.connect('mongodb://127.0.0.1:27017/addzy')
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => console.error('❌ MongoDB connection error:', err));

// Schemas
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    password: { type: String, required: true },
    avatar: { type: String, default: '' },
    bio: { type: String, default: '' },
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
});

const postSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['image', 'video'], required: true },
    mediaUrl: { type: String, required: true },
    caption: { type: String, default: '' },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    comments: [{
        userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        text: String,
        createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
    mediaUrl: { type: String, default: '' },
    seen: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Message = mongoose.model('Message', messageSchema);

// File Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// Authentication Middleware
const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) throw new Error();
        
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        if (!user) throw new Error();
        
        req.user = user;
        req.token = token;
        next();
    } catch (e) {
        res.status(401).json({ error: 'Please authenticate' });
    }
};

// Routes

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, username, name, password } = req.body;
        
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            email,
            username: username.toLowerCase(),
            name,
            password: hashedPassword,
            avatar: `https://api.dicebear.com/7.x/avataaars/svg?seed=${username}`
        });
        
        await user.save();
        
        const token = jwt.sign({ userId: user._id }, JWT_SECRET);
        res.status(201).json({ token, user: { ...user._doc, password: undefined } });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ 
            $or: [{ username: username.toLowerCase() }, { email: username.toLowerCase() }] 
        });
        
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ userId: user._id }, JWT_SECRET);
        res.json({ token, user: { ...user._doc, password: undefined } });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get Current User
app.get('/api/user/me', auth, async (req, res) => {
    res.json(req.user);
});

// Update Profile
app.patch('/api/user/profile', auth, async (req, res) => {
    const updates = Object.keys(req.body);
    const allowedUpdates = ['name', 'bio', 'avatar'];
    const isValidOperation = updates.every(update => allowedUpdates.includes(update));
    
    if (!isValidOperation) {
        return res.status(400).json({ error: 'Invalid updates' });
    }
    
    try {
        updates.forEach(update => req.user[update] = req.body[update]);
        await req.user.save();
        res.json(req.user);
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// Get All Users (for search/discovery)
app.get('/api/users', auth, async (req, res) => {
    try {
        const users = await User.find({ _id: { $ne: req.user._id } })
            .select('-password')
            .limit(20);
        res.json(users);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get User Profile
app.get('/api/users/:username', auth, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username.toLowerCase() })
            .select('-password')
            .populate('followers', 'username name avatar')
            .populate('following', 'username name avatar');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const posts = await Post.find({ userId: user._id })
            .sort({ createdAt: -1 })
            .populate('userId', 'username avatar');
        
        res.json({ user, posts });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Create Post
app.post('/api/posts', auth, upload.single('media'), async (req, res) => {
    try {
        const { caption, type } = req.body;
        const post = new Post({
            userId: req.user._id,
            type,
            mediaUrl: `/uploads/${req.file.filename}`,
            caption
        });
        await post.save();
        await post.populate('userId', 'username avatar name');
        res.status(201).json(post);
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// Get Feed (all posts)
app.get('/api/posts/feed', auth, async (req, res) => {
    try {
        const posts = await Post.find()
            .sort({ createdAt: -1 })
            .populate('userId', 'username avatar name')
            .limit(50);
        res.json(posts);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get User Posts
app.get('/api/posts/user/:userId', auth, async (req, res) => {
    try {
        const posts = await Post.find({ userId: req.params.userId })
            .sort({ createdAt: -1 })
            .populate('userId', 'username avatar name');
        res.json(posts);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Like/Unlike Post
app.post('/api/posts/:postId/like', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.postId);
        if (!post) return res.status(404).json({ error: 'Post not found' });
        
        const likeIndex = post.likes.indexOf(req.user._id);
        if (likeIndex === -1) {
            post.likes.push(req.user._id);
        } else {
            post.likes.splice(likeIndex, 1);
        }
        await post.save();
        res.json({ likes: post.likes.length, liked: likeIndex === -1 });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Add Comment
app.post('/api/posts/:postId/comment', auth, async (req, res) => {
    try {
        const { text } = req.body;
        const post = await Post.findById(req.params.postId);
        if (!post) return res.status(404).json({ error: 'Post not found' });
        
        post.comments.push({ userId: req.user._id, text });
        await post.save();
        await post.populate('comments.userId', 'username avatar');
        res.json(post.comments);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Messaging Routes

// Get Conversations
app.get('/api/messages/conversations', auth, async (req, res) => {
    try {
        const messages = await Message.find({
            $or: [{ senderId: req.user._id }, { receiverId: req.user._id }]
        }).sort({ createdAt: -1 });

        // Group by conversation partner
        const conversations = {};
        messages.forEach(msg => {
            const partnerId = msg.senderId.toString() === req.user._id.toString() 
                ? msg.receiverId.toString() 
                : msg.senderId.toString();
            
            if (!conversations[partnerId]) {
                conversations[partnerId] = {
                    partnerId,
                    lastMessage: msg,
                    unread: msg.receiverId.toString() === req.user._id.toString() && !msg.seen ? 1 : 0
                };
            } else if (msg.receiverId.toString() === req.user._id.toString() && !msg.seen) {
                conversations[partnerId].unread++;
            }
        });

        // Populate partner info
        const partnerIds = Object.keys(conversations);
        const partners = await User.find({ _id: { $in: partnerIds } }).select('username name avatar');
        
        const result = partners.map(partner => ({
            user: partner,
            lastMessage: conversations[partner._id.toString()].lastMessage,
            unreadCount: conversations[partner._id.toString()].unread
        }));

        res.json(result);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get Messages with User
app.get('/api/messages/:userId', auth, async (req, res) => {
    try {
        const messages = await Message.find({
            $or: [
                { senderId: req.user._id, receiverId: req.params.userId },
                { senderId: req.params.userId, receiverId: req.user._id }
            ]
        }).sort({ createdAt: 1 })
        .populate('senderId', 'username avatar')
        .populate('receiverId', 'username avatar');

        // Mark messages as seen
        await Message.updateMany(
            { senderId: req.params.userId, receiverId: req.user._id, seen: false },
            { seen: true }
        );

        res.json(messages);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Send Message
app.post('/api/messages', auth, async (req, res) => {
    try {
        const { receiverId, text, mediaUrl } = req.body;
        const message = new Message({
            senderId: req.user._id,
            receiverId,
            text,
            mediaUrl
        });
        await message.save();
        await message.populate('senderId receiverId', 'username avatar');
        res.status(201).json(message);
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// Follow/Unfollow User
app.post('/api/users/:userId/follow', auth, async (req, res) => {
    try {
        const userToFollow = await User.findById(req.params.userId);
        if (!userToFollow) return res.status(404).json({ error: 'User not found' });
        
        const isFollowing = req.user.following.includes(userToFollow._id);
        
        if (isFollowing) {
            req.user.following.pull(userToFollow._id);
            userToFollow.followers.pull(req.user._id);
        } else {
            req.user.following.push(userToFollow._id);
            userToFollow.followers.push(req.user._id);
        }
        
        await req.user.save();
        await userToFollow.save();
        
        res.json({ 
            following: !isFollowing,
            followersCount: userToFollow.followers.length 
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Search Users
app.get('/api/users/search/:query', auth, async (req, res) => {
    try {
        const users = await User.find({
            $and: [
                { _id: { $ne: req.user._id } },
                {
                    $or: [
                        { username: { $regex: req.params.query, $options: 'i' } },
                        { name: { $regex: req.params.query, $options: 'i' } }
                    ]
                }
            ]
        }).select('-password').limit(20);
        res.json(users);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.listen(PORT, () => {
    console.log(`✅ Addzy Server running on port ${PORT}`);
    console.log(`📡 API Base URL: http://localhost:${PORT}/api`);
    console.log(`💾 MongoDB: Connected to localhost:27017`);
});