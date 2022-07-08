const express = require('express');
const router = express.Router();
const user = require('../model/user');
const bcryptjs = require('bcryptjs');
const passport = require('passport');
require('./passportLocal')(passport);
require('./googleAuth')(passport);
const userRoutes = require('./accountRoutes');

function checkAuth(req, res, next) {
  if (req.isAuthenticated()) {
    res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, post-check=0, pre-check=0');
    next();
  } else {
    req.flash('error_messages', "Please Login to continue !");
    res.redirect('/login');
  }
}

router.get('/', (req, res) => {
  const raws = [
    { title: `Funny Cats Videos Compilation 😂 Cat Reaction Try Not To Laugh Funniest Videos`, url: `https://www.youtube.com/watch?v=Dij7-MGclVk`, like: 10, unlike: 20, tags: `try_not_to_laugh, pet, funny, pets, funny_animal_videos, funny_dogs, funny_cats` },
    { title: `Paul van Dyk & Sue McLaren - Guiding Light (Official Music Video)`, url: `https://www.youtube.com/watch?v=0t6U9iRgD7k`, like: 10, unlike: 20, tags: `Funny, paul, val , dyk, sua, mclaren` },
    { title: `HOUSE LAK 2022 - Mixset - Made For Lak By Carlos`, url: `https://www.youtube.com/watch?v=TlxrusG6T7Q`, like: 10, unlike: 20, tags: `Mixtape, Mixset, Remix, Track, Vietmix, Vietdeep, Vietlak, Viethouse, Vinaviet, Indaviet, Vinahouse, Indahouse, Deephouse, Ghouse, TropcailHouse, Chill, Radiochill, Deepchill, ChillHouse, ChillDeep,  Houselak, Techhouse, Deephouse, TưngTửng, Rap, Penthouse, Discohouse, Edm, HipHop, Rap, Vinahey, Nonstop, Trôi từ đầu đến cuối, OKvinahouse, Collection, BayPhòng, BayLak, Vain, Tiktok,  Phiêu Cuốn Nhẹ Nhàng, Reup.Videos.Music, EditVideoMusicVisual, VisualMusic.` },
    { title: `DEEP HOUSE LAK 2022 - Mixset Người Nghe Hệ Thuỷ Summer 30- 4| 1- 5 LĐQT`, url: `https://www.youtube.com/watch?v=lZFFFgpvPys`, like: 10, unlike: 20, tags: `Mixtape, Mixset, Remix, Track, Vietmix, Vietdeep, Vietlak, Viethouse, Vinaviet, Indaviet, Vinahouse, Indahouse, Deephouse, Ghouse, TropcailHouse, Chill, Radiochill, Deepchill, ChillHouse, ChillDeep,  Houselak, Techhouse, Deephouse, TưngTửng, Rap, Penthouse, Discohouse, Edm, HipHop, Rap, Vinahey, Nonstop, Trôi từ đầu đến cuối, OKvinahouse, Collection, BayPhòng, BayLak, Vain, Tiktok,  Phiêu Cuốn Nhẹ Nhàng, Reup.Videos.Music, EditVideoMusicVisual, VisualMusic.` },
    { title: `Funny Animal Videos 2022 😂 - Best Dogs And Cats Videos`, url: `https://www.youtube.com/watch?v=ca_Z71EL58o`, like: 10, unlike: 20, tags: `Funny, animals` },
  ];
  const movies = raws.map(movie => ({...movie, tags: movie.tags.split(',')}))
  console.log(movies);
  return res.render("index", { logged: req.isAuthenticated(), movies })
});

router.get('/login', (req, res) => {
  res.render("login", { csrfToken: req.csrfToken() });
});

router.get('/signup', (req, res) => {
  res.render("signup", { csrfToken: req.csrfToken() });
});

router.post('/signup', (req, res) => {
  // get all the values 
  const { email, username, password, confirmpassword } = req.body;
  // check if the are empty 
  if (!email || !username || !password || !confirmpassword) {
    res.render("signup", { err: "All Fields Required !", csrfToken: req.csrfToken() });
  } else if (password != confirmpassword) {
    res.render("signup", { err: "Password Don't Match !", csrfToken: req.csrfToken() });
  } else {

    // validate email and username and password 
    // skipping validation
    // check if a user exists
    user.findOne({ $or: [{ email }, { username }] }, function (err, data) {
      if (err) throw err;
      if (data) {
        res.render("signup", { err: "User Exists, Try Logging In !", csrfToken: req.csrfToken() });
      } else {
        // generate a salt
        bcryptjs.genSalt(12, (err, salt) => {
          if (err) throw err;
          // hash the password
          bcryptjs.hash(password, salt, (err, hash) => {
            if (err) throw err;
            // save user in db
            user({
              username,
              email,
              password: hash,
              googleId: null,
              provider: 'email',
            }).save((err, data) => {
              if (err) throw err;
              // login the user
              // use req.login
              // redirect , if you don't want to login
              res.redirect('/login');
            });
          })
        });
      }
    });
  }
});

router.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    failureRedirect: '/login',
    successRedirect: '/profile',
    failureFlash: true,
  })(req, res, next);
});

router.get('/logout', (req, res) => {
  req.logout();
  req.session.destroy(function (err) {
    res.redirect('/');
  });
});

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email',] }));

router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
  res.redirect('/profile');
});

router.get('/profile', checkAuth, (req, res) => {
  res.render('profile', { username: req.user.username, verified: req.user.isVerified });
});

router.use(userRoutes);

module.exports = router;