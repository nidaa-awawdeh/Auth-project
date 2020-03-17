require("dotenv/config");
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { verify } = require("jsonwebtoken");
const { hash, compare } = require("bcryptjs");
const { fakeDB } = require("./fakeDB.js");
const {
    createAccessToken,
    createRefreshToken,
    sendAccesstoken,
    sendRefreshToken
} = require("./token.js");
const { isAuth } = require("./isAuth.js");

//1.register auser
//2. login a user
//3. logout a user
//4. setup protected route
// 5. get a new access token with arefresh token

//create express server
const server = express();
//use express middleware for easier cookie  handling
server.use(cookieParser());
server.use(
    cors({
        origin: "http://localhost:4000",
        credentials: true
    })
);

//needed to be able to read body data
server.use(express.json()); //to support json-encoded bodyies
server.use(express.urlencoded({ extended: true })); //support URl encoded bodies

server.listen(process.env.PORT),
    () => {
        console.log("server listening on port ${process.env.PORT}");
    };

//1.register a user
server.post("/register", async (req, res) => {
    const { email, password } = req.body;
    try {
        // 1. if the user exist
        const user = fakeDB.find(user => user.email === email);
        if (user) throw new Error("User already exist");
        //2. if not user exist hash the password
        const hashPassword = await hash(password, 10);
        // 10 is how time can sort
        //3. insert the user in database
        fakeDB.push({
            id: fakeDB.length,
            email,
            password: hashPassword
        });
        res.send({ message: "user created" });
        //console.log(hashPassword);
        console.log(fakeDB);
    } catch (err) {
        res.send({
            error: `${err.message}`
        });
    }
});

//login a user

server.post("./login", async (req, res) => {
    const { email, password } = req.body;
    try {
        //1- find user in database if not exist send error
        const user = fakeDB.find(user => user.email === email);
        if (!user) throw new Error("User not exist");
        //2-compare crypted password and see if it checks out.send error if not
        const valid = await compare(password, user.password);
        if (!valid) throw new Error("password not correct ");
        // 3-but if correct we can create refresh and access token
        const acesstoken = createAccessToken(user.id);
        const refreshtoken = createRefreshToken(user.id);
        // 4. put the RefreshToken in database
        user.refreshtoken = refreshtoken;
        console.log(fakeDB);
        // 5. send token  refreshtoken as cookie and accesstoken as a regular responce
        sendRefreshToken(res, refreshtoken);
        createAccessToken(res, req, accessToken);
    } catch (err) {
        res.send({
            error: `${err.message}`
        });
    }
});

// 3.logout a user
server.post("/logout", (_req, res) => {
    res.clearCookie("refreshtoken", { path: '/refresh_token' });
    return res.send({
        message: "logged out"
    });
});
// 4.Protected route
server.post("/protected", async (req, res) => {
    try {
        const userId = isAuth(req);
        if (userId !== null) {
            res.send({
                data: " This is protected data. "
            });
        }
    } catch (err) {
        res.send({
            error: `${err.message}`
        });
    }
});

//5. Get a new access token with a refresh token
server.post("/refresh_token", (req, res) => {
    const token = req.cookies.refreshtoken;
    // if we don't  have a token in our request
    if (!token) return res.send({ accesstoken: "" });
    // we have a token , let's verify it;
    let payload = null;
    try {
        payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
    } catch (err) {
        return res.send({ accesstoken: "" });
    }
    //Token is valid ,check if user exist
    const user = fakeDB.find(user => user.id === payload.userId);
    if (!user) return res.send({ accesstoken: '' });
    // user exist ,check if refreshtoken exist on user
    if (user.refreshtoken !== token) {
        return res.send({ accesstoken: '' });
    }
    //token exist ,create new refresh and accesstoken
    const accesstoken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);
    user.refreshtoken = refreshtoken;
    // send new refreshtoken and accesstoken
    sendRefreshToken(res, refreshtoken);
    return res.send({ accesstoken });
});

server.listen(process.env.PORT, () =>
    console.log(`Server listening on port ${process.env.PORT}!`)
);
