'use strict';

const fs = require('fs'),
      path = require('path');

const assert = require('assertthat'),
      express = require('express'),
      jwt = require('jsonwebtoken'),
      request = require('supertest');

const Limes = require('../../src/Limes');

/* eslint-disable no-sync */
const certificate = fs.readFileSync(path.join(__dirname, '..', 'shared', 'keys', 'certificate.pem')),
      privateKey = fs.readFileSync(path.join(__dirname, '..', 'shared', 'keys', 'privateKey.pem'));
/* eslint-enable no-sync */

suite('Limes', () => {
  test('is a function.', async () => {
    assert.that(Limes).is.ofType('function');
  });

  test('throws an exception if options are missing.', async () => {
    assert.that(() => {
      /* eslint-disable no-new */
      new Limes();
      /* eslint-enable no-new */
    }).is.throwing('Options are missing.');
  });

  test('throws an exception if identity provider name is missing.', async () => {
    assert.that(() => {
      /* eslint-disable no-new */
      new Limes({});
      /* eslint-enable no-new */
    }).is.throwing('Identity provider name is missing.');
  });

  test('throws an exception if private key and certificate are both missing.', async () => {
    assert.that(() => {
      /* eslint-disable no-new */
      new Limes({
        identityProviderName: 'auth.example.com'
      });
      /* eslint-enable no-new */
    }).is.throwing('Specify private key and / or certificate.');
  });

  suite('issueTokenFor', () => {
    test('is a function.', async () => {
      const limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey,
        certificate
      });

      assert.that(limes.issueTokenFor).is.ofType('function');
    });

    test('throws an exception if subject is missing.', async () => {
      const limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey,
        certificate
      });

      assert.that(() => {
        limes.issueTokenFor();
      }).is.throwing('Subject is missing.');
    });

    test('returns a JWT.', async () => {
      const limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey,
        certificate
      });

      const token = limes.issueTokenFor('test.domain.com', { foo: 'bar' });

      const decodedToken = await jwt.verify(token, certificate, { issuer: 'auth.example.com' });

      assert.that(decodedToken.iss).is.equalTo('auth.example.com');
      assert.that(decodedToken.sub).is.equalTo('test.domain.com');
      assert.that(decodedToken.foo).is.equalTo('bar');
    });
  });

  suite('issueTokenForAnonymous', () => {
    test('is a function.', async () => {
      const limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey,
        certificate
      });

      assert.that(limes.issueTokenForAnonymous).is.ofType('function');
    });

    test('returns a JWT.', async () => {
      const limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey,
        certificate
      });

      const token = limes.issueTokenForAnonymous({ foo: 'bar' });

      const decodedToken = await jwt.verify(token, certificate, { issuer: 'auth.example.com' });

      assert.that(decodedToken.iss).is.equalTo('auth.example.com');
      assert.that(decodedToken.sub).is.equalTo('anonymous');
      assert.that(decodedToken.foo).is.equalTo('bar');
    });
  });

  suite('verifyToken', () => {
    test('is a function.', async () => {
      const limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey,
        certificate
      });

      assert.that(limes.verifyToken).is.ofType('function');
    });

    test('returns the decoded token if the token is valid.', async () => {
      const limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey,
        certificate
      });

      const token = limes.issueTokenFor('adc225b7-65b9-48f4-be4d-c5108aa4d1f4', {
        foo: 'bar'
      });

      const decodedToken = await limes.verifyToken(token);

      assert.that(decodedToken.iss).is.equalTo('auth.example.com');
      assert.that(decodedToken.sub).is.equalTo('adc225b7-65b9-48f4-be4d-c5108aa4d1f4');
      assert.that(decodedToken.foo).is.equalTo('bar');
    });

    test('throws an error if the token is not valid.', async () => {
      const limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey,
        certificate
      });

      await assert.that(async () => {
        await limes.verifyToken('invalidtoken');
      }).is.throwingAsync('jwt malformed');
    });

    test('throws an error if the token contains invalid characters.', async () => {
      const limes = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey,
        certificate
      });

      await assert.that(async () => {
        await limes.verifyToken('invalid token');
      }).is.throwingAsync('jwt malformed');
    });
  });

  suite('middleware integration', () => {
    let limesInThePast,
        limesOfSomebodyElse;

    suiteSetup(() => {
      limesInThePast = new Limes({
        identityProviderName: 'auth.example.com',
        privateKey,
        certificate,
        expiresInMinutes: -5
      });

      limesOfSomebodyElse = new Limes({
        identityProviderName: 'somebodyelse.example.com',
        privateKey,
        certificate
      });
    });

    suite('verifyTokenMiddlewareExpress', () => {
      test('is a function.', async () => {
        const limes = new Limes({
          identityProviderName: 'auth.example.com',
          privateKey,
          certificate
        });

        assert.that(limes.verifyTokenMiddlewareExpress).is.ofType('function');
      });

      test('returns a function.', async () => {
        const limes = new Limes({
          identityProviderName: 'auth.example.com',
          privateKey,
          certificate
        });

        const middleware = limes.verifyTokenMiddlewareExpress();

        assert.that(middleware).is.ofType('function');
      });

      suite('middleware', () => {
        let app,
            limes;

        setup(() => {
          limes = new Limes({
            identityProviderName: 'auth.example.com',
            privateKey,
            certificate
          });

          app = express();
          app.use(limes.verifyTokenMiddlewareExpress({
            payloadWhenAnonymous: {
              foo: 'anonymous-bar'
            }
          }));
          app.get('/', (req, res) => {
            res.send(req.user);
          });
        });

        test('returns an anonymous token for non-authenticated requests.', done => {
          request(app).
            get('/').
            set('accept', 'application/json').
            end((err, res) => {
              assert.that(err).is.null();
              assert.that(res.statusCode).is.equalTo(200);
              assert.that(res.body.iss).is.equalTo('auth.example.com');
              assert.that(res.body.sub).is.equalTo('anonymous');
              assert.that(res.body.foo).is.equalTo('anonymous-bar');
              done();
            });
        });

        test('returns 401 for invalid authenticated requests.', done => {
          request(app).
            get('/').
            set('accept', 'application/json').
            set('authorization', 'Bearer invalidtoken').
            end((err, res) => {
              assert.that(err).is.null();
              assert.that(res.statusCode).is.equalTo(401);
              done();
            });
        });

        test('returns 401 for tokens with invalid characters.', done => {
          request(app).
            get('/').
            set('accept', 'application/json').
            set('authorization', 'Bearer invalid token').
            end((err, res) => {
              assert.that(err).is.null();
              assert.that(res.statusCode).is.equalTo(401);
              done();
            });
        });

        test('returns 401 for expired requests.', done => {
          const expiredToken = limesInThePast.issueTokenFor('test.domain.com', {
            foo: 'authenticated-bar'
          });

          request(app).
            get('/').
            set('accept', 'application/json').
            set('authorization', `Bearer ${expiredToken}`).
            end((err, res) => {
              assert.that(err).is.null();
              assert.that(res.statusCode).is.equalTo(401);
              done();
            });
        });

        test('returns 401 for authenticated requests with wrong issuer.', done => {
          const token = limesOfSomebodyElse.issueTokenFor('test.domain.com', {
            foo: 'authenticated-bar'
          });

          request(app).
            get('/').
            set('accept', 'application/json').
            set('authorization', `Bearer ${token}`).
            end((err, res) => {
              assert.that(err).is.null();
              assert.that(res.statusCode).is.equalTo(401);
              done();
            });
        });

        test('returns a decoded token for authenticated requests.', done => {
          const token = limes.issueTokenFor('test.domain.com', {
            foo: 'authenticated-bar'
          });

          request(app).
            get('/').
            set('accept', 'application/json').
            set('authorization', `Bearer ${token}`).
            end((err, res) => {
              assert.that(err).is.null();
              assert.that(res.statusCode).is.equalTo(200);
              assert.that(res.body.iss).is.equalTo('auth.example.com');
              assert.that(res.body.sub).is.equalTo('test.domain.com');
              assert.that(res.body.foo).is.equalTo('authenticated-bar');
              done();
            });
        });

        test('returns a decoded token for authenticated requests using query string.', done => {
          const token = limes.issueTokenFor('test.domain.com', {
            foo: 'authenticated-bar'
          });

          request(app).
            get(`/?token=${token}`).
            set('accept', 'application/json').
            end((err, res) => {
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
  });
});
