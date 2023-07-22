const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());
app.listen(5000, () => console.log('Backend server is running'));
app.use((req, res, next) => {
	res.header('Access-Control-Allow-Origin', '*');
	res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
	res.header(
		'Access-Control-Allow-Headers',
		'Origin, X-Requested-With, Content-Type, Accept'
	);
	next();
});

const users = [
	{
		id: '1',
		username: 'John Doe',
		password: 'test@123',
		isAdmin: true,
	},
	{
		id: '2',
		username: 'Mary Jane',
		password: 'Abc@123',
		isAdmin: false,
	},
];

// Refresh token api :

let refreshTokens = [];
app.post('/api/refresh', (req, res) => {
	//take the refresh token from the user
	const refreshToken = req.body.token;

	//send error if there is no token or it's invalid
	if (!refreshToken) return res.status(401).json('You are not authenticated!');
	if (!refreshTokens.includes(refreshToken)) {
		return res.status(403).json('Refresh token is not valid!');
	}

	//if everything is ok, create new access token, refresh token and send to user
	jwt.verify(refreshToken, 'myRefreshSecretKey', (err, user) => {
		err && console.log(err);
		// if refresh Token exists in the array, then delete it
		refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

		const newAccessToken = generateAccessToken(user);
		const newRefreshToken = generateRefreshToken(user);

		refreshTokens.push(newRefreshToken);

		res.status(200).json({
			accessToken: newAccessToken,
			refreshToken: newRefreshToken,
		});
	});
});
app.get('/api/users', (req, res) => {
	res.json(users);
});

// generate access token
const generateAccessToken = (user) => {
	return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, 'mySecretKey', {
		expiresIn: '15s',
	});
};

// generate refresh token
const generateRefreshToken = (user) => {
	return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, 'myRefreshSecretKey');
};

//   POST LOGIN

app.post('/api/login', (req, res) => {
	const { username, password } = req.body;

	const user = users.find((u) => {
		// res.json('Login successful');
		return u.username === username && u.password === password;
	});
	if (user) {
		const accessToken = generateAccessToken(user);
		const refreshToken = generateRefreshToken(user);
		refreshTokens.push(refreshToken);
		res.json({
			username: user.username,
			isAdmin: user.isAdmin,
			accessToken,
			refreshToken,
		});
	} else {
		res.status(400).json('Username or password not found');
	}
});

// verify authToken-> middleware
const verify = (req, res, next) => {
	const authHeader = req.headers.authorization;
	if (authHeader) {
		const token = authHeader.split(' ')[1];
		// console.log('AuthToken:', token);
		jwt.verify(token, 'mySecretKey', (err, user) => {
			if (err) {
				return res.status(403).json('Token is not valid');
			}
			req.user = user;
			next();
		});
	} else {
		res.status(401).json('Not authenticated');
	}
};

// delete api
app.delete('/api/users/:userId', verify, (req, res) => {
	if (req.user.id === req.params.userId || req.user.isAdmin) {
		res.status(200).json('User has been deleted');
	} else {
		res.status(403).json('Permission restricted to delete user');
	}
});

// POST LOGOUT

app.post('/api/logout', verify, (req, res) => {
	const refreshToken = req.body.token;
	refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
	res.status(200).json('You logged out successfully');
});
