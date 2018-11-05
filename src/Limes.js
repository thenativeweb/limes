'use strict';

const expressJwt = require('express-jwt'),
      flow = require('middleware-flow'),
      jwt = require('jsonwebtoken');

class Limes {
  constructor (options) {
    if (!options) {
      throw new Error('Options are missing.');
    }
    if (!options.identityProviderName) {
      throw new Error('Identity provider name is missing.');
    }
    if (!options.privateKey && !options.certificate) {
      throw new Error('Specify private key and / or certificate.');
    }

    const {
      identityProviderName,
      privateKey,
      certificate,
      expiresInMinutes = 24 * 60
    } = options;

    this.identityProviderName = identityProviderName;
    this.privateKey = privateKey;
    this.certificate = certificate;
    this.expiresInMinutes = expiresInMinutes;
  }

  issueTokenFor (subject, payload = {}) {
    if (!subject) {
      throw new Error('Subject is missing.');
    }

    return jwt.sign(payload, this.privateKey, {
      algorithm: 'RS256',
      expiresIn: this.expiresInMinutes * 60,
      subject,
      issuer: this.identityProviderName
    });
  }

  issueTokenForAnonymous (payload) {
    return this.issueTokenFor('anonymous', payload);
  }

  issueDecodedTokenForAnonymous (options) {
    const { payloadWhenAnonymous } = options;

    const issuedAt = Math.floor(Date.now() / 1000);
    const expiresAt = issuedAt + (this.expiresInMinutes * 60);

    const token = payloadWhenAnonymous;

    token.iat = issuedAt;
    token.exp = expiresAt;
    token.iss = this.identityProviderName;
    token.sub = 'anonymous';

    return token;
  }

  async verifyToken (token) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, this.certificate, {
        issuer: this.identityProviderName
      }, (err, decodedToken) => {
        if (err) {
          return reject(err);
        }

        resolve(decodedToken);
      });
    });
  }

  verifyTokenMiddlewareExpress (options = {}) {
    const { payloadWhenAnonymous = {}} = options;

    return flow.
      try(expressJwt({
        secret: this.certificate,
        issuer: this.identityProviderName,
        getToken (req) {
          if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
            return req.headers.authorization.split(' ')[1];
          } else if (req.query && req.query.token) {
            return req.query.token;
          }

          return null;
        }
      })).
      catch((err, req, res, next) => {
        if (err.code === 'invalid_token') {
          return res.status(401).end();
        }

        req.user = this.issueDecodedTokenForAnonymous({ payloadWhenAnonymous });
        next();
      });
  }
}

module.exports = Limes;
