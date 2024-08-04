const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');
require('dotenv').config();

const app = express();
app.use(express.json());

const port = process.env.PORT || 3000;

const sequelize = new Sequelize(process.env.DB_URL, {
    dialect: 'postgres',
    logging: false,
    dialectOptions: {
        ssl: {
            require: true,
            rejectUnauthorized: false,
        },
    },
});

const User = sequelize.define('user', {
    user_id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
    },
    username: {
        type: DataTypes.STRING(50),
        unique: true,
        allowNull: false,
    },
    password: {
        type: DataTypes.STRING(255),
        allowNull: false,
    },
    name: {
        type: DataTypes.STRING(100),
    },
    gender: {
        type: DataTypes.STRING(10),
    },
    is_admin: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
    },
});

const Train = sequelize.define('train', {
    train_id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
    },
    train_name: {
        type: DataTypes.STRING(100),
        allowNull: false,
    },
    source: {
        type: DataTypes.STRING(100),
        allowNull: false,
    },
    destination: {
        type: DataTypes.STRING(100),
        allowNull: false,
    },
    seat_capacity: {
        type: DataTypes.INTEGER,
        allowNull: false,
    },
    arrival_time_at_source: {
        type: DataTypes.DATE,
    },
    arrival_time_at_destination: {
        type: DataTypes.DATE,
    },
});

const Booking = sequelize.define('booking', {
    booking_id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
    },
    user_id: {
        type: DataTypes.INTEGER,
        references: {
            model: User,
            key: 'user_id',
        },
    },
    train_id: {
        type: DataTypes.INTEGER,
        references: {
            model: Train,
            key: 'train_id',
        },
    },
    no_of_seats: {
        type: DataTypes.INTEGER,
        allowNull: false,
    },
    booking_time: {
        type: DataTypes.DATE,
    },
    username: {
        type: DataTypes.STRING(50),
    },
});

sequelize.sync()
    .then(() => console.log('Database synced'))
    .catch((err) => console.error('Error syncing database:', err));

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const isAdmin = async (req, res, next) => {
    const { userId } = req.user;
    const user = await User.findByPk(userId);
    if (user && user.is_admin) {
        next();
    } else {
        res.status(403).send('Access denied');
    }
};

app.post('/register', async (req, res) => {
    const { username, password, name, gender, isAdmin } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const user = await User.create({
            username,
            password: hashedPassword,
            name,
            gender,
            is_admin: isAdmin,
        });
        res.status(201).send('User created successfully');
    } catch (err) {
        res.status(400).send('User already exists');
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ where: { username } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).send('Invalid credentials');
    }
    const token = jwt.sign(
        { userId: user.user_id, username: user.username, isAdmin: user.is_admin },
        process.env.JWT_SECRET
    );
    res.json({ token });
});

app.post('/api/trains/create', authenticateToken, isAdmin, async (req, res) => {
    const { train_name, source, destination, seat_capacity, arrival_time_at_source, arrival_time_at_destination } = req.body;
    try {
        const train = await Train.create({
            train_name,
            source,
            destination,
            seat_capacity,
            arrival_time_at_source,
            arrival_time_at_destination,
        });
        res.status(201).send('Train created successfully');
    } catch (err) {
        res.status(400).send('Error creating train');
    }
});

app.get('/api/trains/availability', async (req, res) => {
    const { source, destination } = req.query;
    try {
        const trains = await Train.findAll({ where: { source, destination } });
        res.json(trains);
    } catch (err) {
        res.status(400).send('Error fetching trains');
    }
});

app.post('/api/trains/:trainId/book', authenticateToken, async (req, res) => {
    const { trainId } = req.params;
    const { no_of_seats } = req.body;
    const { userId, username } = req.user;
    try {
        const train = await Train.findByPk(trainId);
        if (train.seat_capacity < no_of_seats) {
            return res.status(400).send('Not enough seats available');
        }
        const booking_time = new Date();
        const booking = await Booking.create({
            user_id: userId,
            train_id: trainId,
            no_of_seats,
            booking_time,
            username,
        });
        await train.update({ seat_capacity: train.seat_capacity - no_of_seats });
        res.status(201).send('Seats booked successfully');
    } catch (err) {
        res.status(400).send('Error booking seats');
    }
});

app.get('/api/bookings/:bookingId', authenticateToken, async (req, res) => {
    const { bookingId } = req.params;
    const { userId } = req.user;
    try {
        const booking = await Booking.findOne({ where: { booking_id: bookingId, user_id: userId } });
        if (!booking) {
            return res.status(404).send('Booking not found');
        }
        res.json(booking);
    } catch (err) {
        res.status(400).send('Error fetching booking');
    }
});
app.get('/api/bookings/', authenticateToken, async (req, res) => {
    const { userId } = req.user;
    try {
        const booking = await Booking.findOne({ where: {  user_id: userId } });
        if (!booking) {
            return res.status(404).send('Booking not found');
        }
        res.json(booking);
    } catch (err) {
        res.status(400).send('Error fetching booking');
    }
});

app.listen(port, () => {
    console.log(`App is listening at http://localhost:${port}`);
});
