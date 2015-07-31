'use strict';

var expressJwt = require('express-jwt'),
    flow = require('middleware-flow'),
    jwt = require('jsonwebtoken');

var Limes = function (options) {
  if (!options) {
    throw new Error('Options are missing.');
  }

  if (!options.identityProviderName) {
    throw new Error('Identity provider name is missing.');
  }

  if (!options.privateKey && !options.certificate) {
    throw new Error('Specify private key and / or certificate.');
  }

  this.identityProviderName = options.identityProviderName;
  this.privateKey = options.privateKey;
  this.certificate = options.certificate;

  this.expiresInMinutes = options.expiresInMinutes || (24 * 60);
};

Limes.prototype.issueTokenFor = function (subject, payload) {
  if (!subject && subject !== '') {
    throw new Error('Subject is missing.');
  }

  payload = payload || {};

  return jwt.sign(payload, this.privateKey, {
    algorithm: 'RS256',
    expiresInMinutes: this.expiresInMinutes,
    subject: subject,
    issuer: this.identityProviderName
  });
};

Limes.prototype.issueTokenForAnonymous = function (payload) {
  return this.issueTokenFor('', payload);
};

Limes.prototype.issueDecodedTokenForAnonymous = function (options) {
  var expiresAt,
      issuedAt,
      token;

  issuedAt = Math.floor(Date.now() / 1000);
  expiresAt = issuedAt + (this.expiresInMinutes * 60);

  token = options.payloadWhenAnonymous;

  token.iat = issuedAt;
  token.exp = expiresAt;
  token.iss = this.identityProviderName;
  token.sub = undefined;

  return token;
};

Limes.prototype.verifyToken = function (token, callback) {
  jwt.verify(token, this.certificate, {
    issuer: this.identityProviderName
  }, callback);
};

Limes.prototype.verifyTokenMiddlewareExpress = function (options) {
  var that = this;

  options = options || {};
  options.payloadWhenAnonymous = options.payloadWhenAnonymous || {};

  return flow.
    try(expressJwt({
      secret: that.certificate,
      issuer: that.identityProviderName,
      getToken: function fromHeaderOrQuerystring (req) {
        if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
          return req.headers.authorization.split(' ')[1];
        } else if (req.query && req.query.token) {
          return req.query.token;
        }
        return null;
      }
    })).
    catch(function (err, req, res, next) {
      if (err.code === 'invalid_token') {
        return res.status(401).end();
      }

      req.user = that.issueDecodedTokenForAnonymous(options);
      next();
    });
};

Limes.prototype.verifyTokenMiddlewareSocketIo = function (options) {
  var that = this;

  options = options || {};
  options.payloadWhenAnonymous = options.payloadWhenAnonymous || {};

  return function (socket, next) {
    socket.on('authenticate', function (token, callback) {
      callback = callback || function () {};

      if (!token) {
        return callback({ message: 'Token is missing.' });
      }

      that.verifyToken(token, function (err, decodedToken) {
        if (err) {
          return callback({ message: 'Token is invalid.' });
        }

        socket.user = decodedToken;

        callback(null);
        next();
      });
    });

    socket.user = that.issueDecodedTokenForAnonymous(options);
    next();
  };
};

module.exports = Limes;
