const fs = require('fs')

module.exports = {
    devServer: {
        https: {
          key: fs.readFileSync('./certs/front.key.pem'),
          cert: fs.readFileSync('./certs/front.crt.pem'),
        },
        public: 'https://localhost:'
    }
  }