// quick Node snippet (run with node -e "..."):
const bcrypt = require('bcrypt');
bcrypt.hash('yourStrongPassword', 12).then(h => {
  console.log('Hash:', h);
  // then insert into DB: INSERT INTO users(username,password_hash,is_admin) VALUES('alice','<hash>',1);
});
