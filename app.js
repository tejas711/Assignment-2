const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const bcrypt = require('bcryptjs');


const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());

mongoose.connect('mongodb://localhost/assignment', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
});

userSchema.pre('save', async function (next) {
    const user = this;
    if (!user.isModified('password')) {
        return next();
    }
    const salt = await bcrypt.genSalt();
    const hash = await bcrypt.hash(user.password, salt);
    user.password = hash;
    next();
});

const postSchema = new mongoose.Schema({
    title: String,
    body: String,
    image: String,
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
    },
});

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        res.json({ status: 'success', data: user });
    } catch (err) {
        res.status(400).json({ status: 'error', message: err.message });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email, password });
        if (user) {
            const token = jwt.sign({ userId: user._id }, 'secret-key');
            res.json({ status: 'success', token });
        } else {
            res.status(401).json({ status: 'error', message: 'Invalid credentials' });
        }
    } catch (err) {
        res.status(400).json({ status: 'error', message: err.message });
    }
});

const authenticate = async (req, res, next) => {
    const token = req.headers.authorization;
    if (token) {
        try {
            const decodedToken = jwt.verify(token, 'secret-key');
            req.userId = decodedToken.userId;
            next();
        } catch (err) {
            res.status(401).json({ status: 'error', message: 'Invalid token' });
        }
    } else {
        res.status(401).json({ status: 'error', message: 'Authorization header missing' });
    }
};

app.get('/posts', async (req, res) => {
    try {
        const posts = await Post.find().populate('user', '-password');
        res.json({ posts });
    } catch (err) {
        res.status(400).json({ status: 'error', message: err.message });
    }
});

app.post('/posts', authenticate, async (req, res) => {
    const { title, body, image } = req.body;
    try {
        const post = new Post({ title, body, image, user: req.userId });
        await post.save();
        res.json({ status: 'post created', data: post });
    } catch (err) {
        res.status(400).json({ status: 'error', message: err.message })
    }
});
app.get('/posts/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const post = await Post.findById(id).populate('user', '-password');
        if (!post) {
            res.status(404).json({ status: 'error', message: 'Post not found' });
        } else {
            res.json({ status: 'success', data: post });
        }
    } catch (err) {
        res.status(400).json({ status: 'error', message: err.message });
    }
});

app.put('/posts/:id', authenticate, async (req, res) => {
    const { id } = req.params;
    const { title, body, image } = req.body;
    try {
        const post = await Post.findById(id);
        if (!post) {
            res.status(404).json({ status: 'error', message: 'Post not found' });
        } else if (post.user.toString() !== req.userId) {
            res.status(401).json({ status: 'error', message: 'Not authorized to edit this post' });
        } else {
            post.title = title || post.title;
            post.body = body || post.body;
            post.image = image || post.image;
            await post.save();
            res.json({ status: 'success', data: post });
        }
    } catch (err) {
        res.status(400).json({ status: 'error', message: err.message });
    }
});

app.delete('/posts/:id', authenticate, async (req, res) => {
    const { id } = req.params;
    try {
        const post = await Post.findById(id);
        if (!post) {
            res.status(404).json({ status: 'error', message: 'Post not found' });
        } else if (post.user.toString() !== req.userId) {
            res.status(401).json({ status: 'error', message: 'Not authorized to delete this post' });
        } else {
            await post.remove();
            res.json({ status: 'success', message: 'Post deleted' });
        }
    } catch (err) {
        res.status(400).json({ status: 'error', message: err.message });
    }
});

app.listen(3000, () => {
    console.log('Server started on port 3000');
});