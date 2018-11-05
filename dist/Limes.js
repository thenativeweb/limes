'use strict';

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

var _regenerator = _interopRequireDefault(require("@babel/runtime/regenerator"));

var _asyncToGenerator2 = _interopRequireDefault(require("@babel/runtime/helpers/asyncToGenerator"));

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime/helpers/createClass"));

var expressJwt = require('express-jwt'),
    flow = require('middleware-flow'),
    jwt = require('jsonwebtoken');

var Limes =
/*#__PURE__*/
function () {
  function Limes(options) {
    (0, _classCallCheck2.default)(this, Limes);

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
        expiresInMinutes = _options$expiresInMin === void 0 ? 24 * 60 : _options$expiresInMin;
    this.identityProviderName = identityProviderName;
    this.privateKey = privateKey;
    this.certificate = certificate;
    this.expiresInMinutes = expiresInMinutes;
  }

  (0, _createClass2.default)(Limes, [{
    key: "issueTokenFor",
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
    key: "issueTokenForAnonymous",
    value: function issueTokenForAnonymous(payload) {
      return this.issueTokenFor('anonymous', payload);
    }
  }, {
    key: "issueDecodedTokenForAnonymous",
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
    key: "verifyToken",
    value: function () {
      var _verifyToken = (0, _asyncToGenerator2.default)(
      /*#__PURE__*/
      _regenerator.default.mark(function _callee(token) {
        var _this = this;

        return _regenerator.default.wrap(function _callee$(_context) {
          while (1) {
            switch (_context.prev = _context.next) {
              case 0:
                return _context.abrupt("return", new Promise(function (resolve, reject) {
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
              case "end":
                return _context.stop();
            }
          }
        }, _callee, this);
      }));

      return function verifyToken(_x) {
        return _verifyToken.apply(this, arguments);
      };
    }()
  }, {
    key: "verifyTokenMiddlewareExpress",
    value: function verifyTokenMiddlewareExpress() {
      var _this2 = this;

      var options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
      var _options$payloadWhenA = options.payloadWhenAnonymous,
          payloadWhenAnonymous = _options$payloadWhenA === void 0 ? {} : _options$payloadWhenA;
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

        req.user = _this2.issueDecodedTokenForAnonymous({
          payloadWhenAnonymous: payloadWhenAnonymous
        });
        next();
      });
    }
  }]);
  return Limes;
}();

module.exports = Limes;