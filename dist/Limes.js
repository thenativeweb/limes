'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var expressJwt = require('express-jwt'),
    flow = require('middleware-flow'),
    jwt = require('jsonwebtoken');

var Limes = function () {
  function Limes(options) {
    _classCallCheck(this, Limes);

    if (!options) {
      throw new Error('Options are missing.');
    }
    if (!options.identityProviderName) {
      throw new Error('Identity provider name is missing.');
    }
    if (!options.privateKey && !options.certificate) {
      throw new Error('Specify private key and / or certificate.');
    }

    var identityProviderName = options.identityProviderName,
        privateKey = options.privateKey,
        certificate = options.certificate,
        _options$expiresInMin = options.expiresInMinutes,
        expiresInMinutes = _options$expiresInMin === undefined ? 24 * 60 : _options$expiresInMin;


    this.identityProviderName = identityProviderName;
    this.privateKey = privateKey;
    this.certificate = certificate;
    this.expiresInMinutes = expiresInMinutes;
  }

  _createClass(Limes, [{
    key: 'issueTokenFor',
    value: function issueTokenFor(subject) {
      var payload = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

      if (!subject) {
        throw new Error('Subject is missing.');
      }

      return jwt.sign(payload, this.privateKey, {
        algorithm: 'RS256',
        expiresIn: this.expiresInMinutes * 60,
        subject: subject,
        issuer: this.identityProviderName
      });
    }
  }, {
    key: 'issueTokenForAnonymous',
    value: function issueTokenForAnonymous(payload) {
      return this.issueTokenFor('anonymous', payload);
    }
  }, {
    key: 'issueDecodedTokenForAnonymous',
    value: function issueDecodedTokenForAnonymous(options) {
      var payloadWhenAnonymous = options.payloadWhenAnonymous;


      var issuedAt = Math.floor(Date.now() / 1000);
      var expiresAt = issuedAt + this.expiresInMinutes * 60;

      var token = payloadWhenAnonymous;

      token.iat = issuedAt;
      token.exp = expiresAt;
      token.iss = this.identityProviderName;
      token.sub = 'anonymous';

      return token;
    }
  }, {
    key: 'verifyToken',
    value: function () {
      var _ref = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee(token) {
        var _this = this;

        return regeneratorRuntime.wrap(function _callee$(_context) {
          while (1) {
            switch (_context.prev = _context.next) {
              case 0:
                return _context.abrupt('return', new Promise(function (resolve, reject) {
                  jwt.verify(token, _this.certificate, {
                    issuer: _this.identityProviderName
                  }, function (err, decodedToken) {
                    if (err) {
                      return reject(err);
                    }

                    resolve(decodedToken);
                  });
                }));

              case 1:
              case 'end':
                return _context.stop();
            }
          }
        }, _callee, this);
      }));

      function verifyToken(_x2) {
        return _ref.apply(this, arguments);
      }

      return verifyToken;
    }()
  }, {
    key: 'verifyTokenMiddlewareExpress',
    value: function verifyTokenMiddlewareExpress() {
      var _this2 = this;

      var options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
      var _options$payloadWhenA = options.payloadWhenAnonymous,
          payloadWhenAnonymous = _options$payloadWhenA === undefined ? {} : _options$payloadWhenA;


      return flow.try(expressJwt({
        secret: this.certificate,
        issuer: this.identityProviderName,
        getToken: function getToken(req) {
          if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
            return req.headers.authorization.split(' ')[1];
          } else if (req.query && req.query.token) {
            return req.query.token;
          }

          return null;
        }
      })).catch(function (err, req, res, next) {
        if (err.code === 'invalid_token') {
          return res.status(401).end();
        }

        req.user = _this2.issueDecodedTokenForAnonymous({ payloadWhenAnonymous: payloadWhenAnonymous });
        next();
      });
    }
  }]);

  return Limes;
}();

module.exports = Limes;