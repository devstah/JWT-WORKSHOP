const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const Sequelize = require('sequelize');
const { STRING } = Sequelize;
const config = {
  logging: false
};

if(process.env.LOGGING){
  delete config.logging;
}
const conn = new Sequelize(process.env.DATABASE_URL || 'postgres://localhost/acme_db', config);

const User = conn.define('user', {
  username: STRING,
  password: STRING
});

User.addHook('beforeSave', async function (user) {
  if (user._changed.has('password')) {
      user.password = await bcrypt.hash(user.password, 5)
  }
})

User.byToken = async(token)=> {
  try {
    const user = await User.findByPk(token);
    if(user){
      return user;
    }
    const error = Error('bad credentials');
    error.status = 401;;
    throw error;
  }
  catch(ex){
    const error = Error('bad credentials');
    error.status = 401;;
    throw error;
  }
};

User.authenticate = async({ username, password })=> {
  const user = await User.findOne({
    where: {
      username
      // password
    }
  });
  // if(user){
  //   // return user.id; //where you are generating the web token
  //   return jwt.sign({id: user.id}, process.env.JWT)
  // }

     //if we dont have a user throw an error
  if (user && (await bcrypt.compare(password, user.password))) {
    return jwt.sign({ id: user.id }, process.env.JWT)
  }

  const error = Error('bad credentials');
  error.status = 401;
  throw error;
};

User.byToken = async function (token) {
  try {
      const { id } = jwt.verify(token, process.env.JWT)
      const user = await User.findByPk(id)
      if (user) {
          return user
      }
      const error = Error('bad credentials')
      error.status = 401
      throw error
  } catch (ex) {
      const error = Error('bad credentials')
      error.status = 401
      throw error
  }
}

const syncAndSeed = async()=> {
  await conn.sync({ force: true });
  const credentials = [
    { username: 'lucy', password: 'lucy_pw'},
    { username: 'moe', password: 'moe_pw'},
    { username: 'larry', password: 'larry_pw'}
  ];
  const [lucy, moe, larry] = await Promise.all(
    credentials.map( credential => User.create(credential))
  );
  return {
    users: {
      lucy,
      moe,
      larry
    }
  };
};

module.exports = {
  syncAndSeed,
  models: {
    User
  }
};
