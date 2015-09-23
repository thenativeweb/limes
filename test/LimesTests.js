'use strict';

var fs = require('fs'),
    http = require('http'),
    path = require('path');

var assert = require('assertthat'),
    express = require('express'),
    jwt = require('jsonwebtoken'),
    request = require('supertest'),
    socketIo = require('socket.io'),
    socketIoClient = require('socket.io-client');

var Limes = require('../lib/Limes');

var certificate = fs.readFileSync(path.join(__dirname, 'keys', 'certificate.pem')),
    privateKey = fs.readFileSync(path.join(__dirname, 'keys', 'privateKey.pem'));

suite('Limes', function () {
  test('is a function.', function (done) {
    assert.that(Limes).is.ofType('function');
    done();
  });

  test('throws an exception if options are missing.', function (done) {
    assert.that(function () {
      /* eslint-disable no-new */
      new Limes();
      /* eslint-enable no-new */
    }).is.throwing('Options are missing.');
    done();
  });

  test('throws an exception if identity provider name is missing.', function (done) {
    assert.that(function () {
      /* eslint-disable no-new */
      new Limes({});
      /* eslint-enable no-new */
    }).is.throwing('Identity provider name is missing.');
    done();
  });

  test('throws an exception if private key and certificate are both missing.', function (done) {
    assert.that(function () {
      /* eslint-disable no-new */
      new Limes({
        identityProviderName: 'auth.example.com'
      });
      /* eslint-enable no-new */
    }).is.throwing('Specify private key and / or certificate.');
    done();
  });

  suite('issueTokenFor', function () {
    test('is a function.', function (done) {
      var limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey: privateKey,
        certificate: certificate
      });

      assert.that(limes.issueTokenFor).is.ofType('function');
      done();
    });

    test('throws an exception if subject is missing.', function (done) {
      var limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey: privateKey,
        certificate: certificate
      });

      assert.that(function () {
        limes.issueTokenFor();
      }).is.throwing('Subject is missing.');
      done();
    });

    test('returns a JWT.', function (done) {
      var limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey: privateKey,
        certificate: certificate
      });

      var token = limes.issueTokenFor('test.domain.com', { foo: 'bar' });

      jwt.verify(token, certificate, { issuer: 'auth.example.com' }, function (err, decodedToken) {
        assert.that(err).is.null();
        assert.that(decodedToken.iss).is.equalTo('auth.example.com');
        assert.that(decodedToken.sub).is.equalTo('test.domain.com');
        assert.that(decodedToken.foo).is.equalTo('bar');
        done();
      });
    });
  });

  suite('issueTokenForAnonymous', function () {
    test('is a function.', function (done) {
      var limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey: privateKey,
        certificate: certificate
      });

      assert.that(limes.issueTokenForAnonymous).is.ofType('function');
      done();
    });

    test('returns a JWT.', function (done) {
      var limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey: privateKey,
        certificate: certificate
      });

      var token = limes.issueTokenForAnonymous({ foo: 'bar' });

      jwt.verify(token, certificate, { issuer: 'auth.example.com' }, function (err, decodedToken) {
        assert.that(err).is.null();
        assert.that(decodedToken.iss).is.equalTo('auth.example.com');
        assert.that(decodedToken.sub).is.undefined();
        assert.that(decodedToken.foo).is.equalTo('bar');
        done();
      });
    });
  });

  suite('verifyToken', function () {
    test('is a function.', function (done) {
      var limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey: privateKey,
        certificate: certificate
      });

      assert.that(limes.verifyToken).is.ofType('function');
      done();
    });

    test('returns the decoded token if the token is valid.', function (done) {
      var limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey: privateKey,
        certificate: certificate
      });

      var token = limes.issueTokenFor('adc225b7-65b9-48f4-be4d-c5108aa4d1f4', {
        foo: 'bar'
      });

      limes.verifyToken(token, function (err, decodedToken) {
        assert.that(err).is.null();
        assert.that(decodedToken.iss).is.equalTo('auth.example.com');
        assert.that(decodedToken.sub).is.equalTo('adc225b7-65b9-48f4-be4d-c5108aa4d1f4');
        assert.that(decodedToken.foo).is.equalTo('bar');
        done();
      });
    });

    test('returns an error if the token is not valid.', function (done) {
      var limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey: privateKey,
        certificate: certificate
      });

      limes.verifyToken('invalidtoken', function (err) {
        assert.that(err).is.not.null();
        done();
      });
    });

    test('returns an error if the token contains invalid characters.', function (done) {
      var limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey: privateKey,
        certificate: certificate
      });

      limes.verifyToken('invalid token', function (err) {
        assert.that(err).is.not.null();
        done();
      });
    });
  });

  suite('middleware integration', function () {
    var limesInThePast,
        limesOfSomebodyElse;

    suiteSetup(function () {
      limesInThePast = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey: privateKey,
        certificate: certificate,
        expiresInMinutes: -5
      });

      limesOfSomebodyElse = new Limes({
        identityProviderName: 'somebodyelse.example.com',
        privateKey: privateKey,
        certificate: certificate
      });
    });

    suite('verifyTokenMiddlewareExpress', function () {
      test('is a function.', function (done) {
        var limes = new Limes({
          identityProviderName: 'auth.example.com',
          privateKey: privateKey,
          certificate: certificate
        });

        assert.that(limes.verifyTokenMiddlewareExpress).is.ofType('function');
        done();
      });

      test('returns a function.', function (done) {
        var limes = new Limes({
          identityProviderName: 'auth.example.com',
          privateKey: privateKey,
          certificate: certificate
        });

        var middleware = limes.verifyTokenMiddlewareExpress();

        assert.that(middleware).is.ofType('function');
        done();
      });

      suite('middleware', function () {
        var app,
            limes;

        setup(function () {
          limes = new Limes({
            identityProviderName: 'auth.example.com',
            privateKey: privateKey,
            certificate: certificate
          });

          app = express();
          app.use(limes.verifyTokenMiddlewareExpress({
            payloadWhenAnonymous: {
              foo: 'anonymous-bar'
            }
          }));
          app.get('/', function (req, res) {
            res.send(req.user);
          });
        });

        test('returns an anonymous token for non-authenticated requests.', function (done) {
          request(app).
            get('/').
            set('accept', 'application/json').
            end(function (err, res) {
              assert.that(err).is.null();
              assert.that(res.statusCode).is.equalTo(200);
              assert.that(res.body.iss).is.equalTo('auth.example.com');
              assert.that(res.body.sub).is.undefined();
              assert.that(res.body.foo).is.equalTo('anonymous-bar');
              done();
            });
        });

        test('returns 401 for invalid authenticated requests.', function (done) {
          request(app).
            get('/').
            set('accept', 'application/json').
            set('authorization', 'Bearer invalidtoken').
            end(function (err, res) {
              assert.that(err).is.null();
              assert.that(res.statusCode).is.equalTo(401);
              done();
            });
        });

        test('returns 401 for tokens with invalid characters.', function (done) {
          request(app).
            get('/').
            set('accept', 'application/json').
            set('authorization', 'Bearer invalid token').
            end(function (err, res) {
              assert.that(err).is.null();
              assert.that(res.statusCode).is.equalTo(401);
              done();
            });
        });

        test('returns 401 for expired requests.', function (done) {
          var expiredToken = limesInThePast.issueTokenFor('test.domain.com', {
            foo: 'authenticated-bar'
          });

          request(app).
            get('/').
            set('accept', 'application/json').
            set('authorization', 'Bearer ' + expiredToken).
            end(function (err, res) {
              assert.that(err).is.null();
              assert.that(res.statusCode).is.equalTo(401);
              done();
            });
        });

        test('returns 401 for authenticated requests with wrong issuer.', function (done) {
          var token = limesOfSomebodyElse.issueTokenFor('test.domain.com', {
            foo: 'authenticated-bar'
          });

          request(app).
            get('/').
            set('accept', 'application/json').
            set('authorization', 'Bearer ' + token).
            end(function (err, res) {
              assert.that(err).is.null();
              assert.that(res.statusCode).is.equalTo(401);
              done();
            });
        });

        test('returns a decoded token for authenticated requests.', function (done) {
          var token = limes.issueTokenFor('test.domain.com', {
            foo: 'authenticated-bar'
          });

          request(app).
            get('/').
            set('accept', 'application/json').
            set('authorization', 'Bearer ' + token).
            end(function (err, res) {
              assert.that(err).is.null();
              assert.that(res.statusCode).is.equalTo(200);
              assert.that(res.body.iss).is.equalTo('auth.example.com');
              assert.that(res.body.sub).is.equalTo('test.domain.com');
              assert.that(res.body.foo).is.equalTo('authenticated-bar');
              done();
            });
        });

        test('returns a decoded token for authenticated requests using query string.', function (done) {
          var token = limes.issueTokenFor('test.domain.com', {
            foo: 'authenticated-bar'
          });

          request(app).
            get('/?token=' + token).
            set('accept', 'application/json').
            end(function (err, res) {
              assert.that(err).is.null();
              assert.that(res.statusCode).is.equalTo(200);
              assert.that(res.body.iss).is.equalTo('auth.example.com');
              assert.that(res.body.sub).is.equalTo('test.domain.com');
              assert.that(res.body.foo).is.equalTo('authenticated-bar');
              done();
            });
        });
      });
    });

    suite('verifyTokenMiddlewareSocketIo', function () {
      test('is a function.', function (done) {
        var limes = new Limes({
          identityProviderName: 'auth.example.com',
          privateKey: privateKey,
          certificate: certificate
        });

        assert.that(limes.verifyTokenMiddlewareSocketIo).is.ofType('function');
        done();
      });

      test('returns a function.', function (done) {
        var limes = new Limes({
          identityProviderName: 'auth.example.com',
          privateKey: privateKey,
          certificate: certificate
        });

        var middleware = limes.verifyTokenMiddlewareSocketIo();

        assert.that(middleware).is.ofType('function');
        done();
      });

      suite('middleware', function () {
        var limes;

        suiteSetup(function () {
          var app,
              io,
              server;

          limes = new Limes({
            identityProviderName: 'auth.example.com',
            privateKey: privateKey,
            certificate: certificate
          });

          app = express();
          server = http.createServer(app);
          io = socketIo.listen(server);
          io.use(limes.verifyTokenMiddlewareSocketIo({
            payloadWhenAnonymous: {
              foo: 'anonymous-bar'
            }
          }));
          io.on('connection', function (socket) {
            socket.on('getUser', function (callback) {
              callback(socket.user);
            });
          });
          server.listen(3000);
        });

        test('returns an anonymous token for non-authenticated requests.', function (done) {
          var socket = socketIoClient.connect('http://localhost:3000', { forceNew: true });

          socket.once('connect', function () {
            socket.emit('getUser', function (token) {
              assert.that(token.iss).is.equalTo('auth.example.com');
              assert.that(token.sub).is.undefined();
              assert.that(token.foo).is.equalTo('anonymous-bar');
              socket.disconnect();
              done();
            });
          });
        });

        test('returns an error for invalid authenticated requests.', function (done) {
          var socket = socketIoClient.connect('http://localhost:3000', { forceNew: true });

          socket.once('connect', function () {
            socket.emit('authenticate', 'invalidtoken', function (err) {
              assert.that(err).is.not.null();
              socket.disconnect();
              done();
            });
          });
        });

        test('returns an error for expired requests.', function (done) {
          var expiredToken = limesInThePast.issueTokenFor('test.domain.com', {
            foo: 'authenticated-bar'
          });

          var socket = socketIoClient.connect('http://localhost:3000', { forceNew: true });

          socket.once('connect', function () {
            socket.emit('authenticate', expiredToken, function (err) {
              assert.that(err).is.not.null();
              socket.disconnect();
              done();
            });
          });
        });

        test('returns an error for authenticated requests with wrong issuer.', function (done) {
          var token = limesOfSomebodyElse.issueTokenFor('test.domain.com', {
            foo: 'authenticated-bar'
          });

          var socket = socketIoClient.connect('http://localhost:3000', { forceNew: true });

          socket.once('connect', function () {
            socket.emit('authenticate', token, function (err) {
              assert.that(err).is.not.null();
              socket.disconnect();
              done();
            });
          });
        });

        test('returns a decoded token for authenticated requests.', function (done) {
          var token = limes.issueTokenFor('test.domain.com', {
            foo: 'authenticated-bar'
          });

          var socket = socketIoClient.connect('http://localhost:3000', { forceNew: true });

          socket.once('connect', function () {
            socket.emit('authenticate', token, function (err) {
              assert.that(err).is.null();
              socket.emit('getUser', function (receivedToken) {
                assert.that(receivedToken.iss).is.equalTo('auth.example.com');
                assert.that(receivedToken.sub).is.equalTo('test.domain.com');
                assert.that(receivedToken.foo).is.equalTo('authenticated-bar');
                socket.disconnect();
                done();
              });
            });
          });
        });
      });
    });
  });
});
