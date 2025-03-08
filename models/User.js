// const mongoose = require('mongoose');

// const userSchema = new mongoose.Schema({
//     name: String,
//     email: String,
//     password: String,
// });

// module.exports = mongoose.model('User', userSchema);

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,  // Name is required
  },
  email: {
    type: String,
    required: true,  // Email is required
    unique: true,    // Email should be unique
    match: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,  // Email format validation
  },
  password: {
    type: String,
    required: true,  // Password is required
    minlength: 6,    // Password should be at least 6 characters
  },
});

module.exports = mongoose.model('User', userSchema);
