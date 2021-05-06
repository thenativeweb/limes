import { assert } from 'assertthat';
import express from 'express';
import { Express } from 'express-serve-static-core';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import path from 'path';
import request from 'supertest';
import { v4 } from 'uuid';
import { IdentityProvider, Limes } from '../../lib/Limes';

/* eslint-disable no-sync */
const keys = {
  thenativeweb: {
    certificate: fs.readFileSync(path.join(__dirname, '..', 'shared', 'keys', 'auth.thenativeweb.io', 'certificate.pem')),
    privateKey: fs.readFileSync(path.join(__dirname, '..', 'shared', 'keys', 'auth.thenativeweb.io', 'privateKey.pem'))
  },
  intuity: {
    certificate: fs.readFileSync(path.join(__dirname, '..', 'shared', 'keys', 'auth.intuity.de', 'certificate.pem')),
    privateKey: fs.readFileSync(path.join(__dirname, '..', 'shared', 'keys', 'auth.intuity.de', 'privateKey.pem'))
  },
  example: {
    certificate: fs.readFileSync(path.join(__dirname, '..', 'shared', 'keys', 'auth.example.com', 'certificate.pem')),
    privateKey: fs.readFileSync(path.join(__dirname, '..', 'shared', 'keys', 'auth.example.com', 'privateKey.pem'))
  }
};
/* eslint-enable no-sync */

suite('Limes', (): void => {
  const identityProviderThenativeweb = new IdentityProvider({
    issuer: 'https://auth.thenativeweb.io',
    privateKey: keys.thenativeweb.privateKey,
    certificate: keys.thenativeweb.certificate
  });

  const identityProviderIntuity = new IdentityProvider({
    issuer: 'https://auth.intuity.de',
    privateKey: keys.intuity.privateKey,
    certificate: keys.intuity.certificate
  });

  const identityProviderUnknown = new IdentityProvider({
    issuer: 'https://auth.example.com',
    privateKey: keys.example.privateKey,
    certificate: keys.example.certificate
  });

  const identityProviderExpired = new IdentityProvider({
    issuer: 'https://auth.thenativeweb.io',
    privateKey: keys.thenativeweb.privateKey,
    certificate: keys.thenativeweb.certificate,
    expiresInMinutes: -5
  });

  let limes: Limes;

  setup(async (): Promise<void> => {
    limes = new Limes({
      identityProviders: [ identityProviderThenativeweb, identityProviderIntuity ]
    });
  });

  suite('IdentityProvider', (): void => {
    test('is the IdentityProvider constructor.', async (): Promise<void> => {
      assert.that(IdentityProvider).is.identicalTo(IdentityProvider);
    });
  });

  suite('getIdentityProviderByIssuer', (): void => {
    test('throws an error if issuer does not exist.', async (): Promise<void> => {
      assert.that((): void => {
        limes.getIdentityProviderByIssuer({ issuer: 'https://auth.example.com' });
      }).is.throwing(`Issuer 'https://auth.example.com' not found.`);
    });

    test('returns the requested identity provider.', async (): Promise<void> => {
      const identityProvider = limes.getIdentityProviderByIssuer({
        issuer: 'https://auth.thenativeweb.io'
      });

      assert.that(identityProvider).is.identicalTo(identityProviderThenativeweb);
    });
  });

  suite('issueToken', (): void => {
    test('returns a JWT.', async (): Promise<void> => {
      const token = limes.issueToken({
        issuer: 'https://auth.thenativeweb.io',
        subject: 'jane.doe'
      });

      const decodedToken = jwt.verify(token, keys.thenativeweb.certificate, { issuer: 'https://auth.thenativeweb.io' }) as Record<string, any>;

      assert.that(decodedToken.iss).is.equalTo('https://auth.thenativeweb.io');
      assert.that(decodedToken.sub).is.equalTo('jane.doe');
    });

    test('returns a JWT with the given payload.', async (): Promise<void> => {
      const token = limes.issueToken({
        issuer: 'https://auth.thenativeweb.io',
        subject: 'jane.doe',
        payload: {
          'https://auth.thenativeweb.io/email': 'jane.doe@thenativeweb.io'
        }
      });

      const decodedToken = jwt.verify(token, keys.thenativeweb.certificate, { issuer: 'https://auth.thenativeweb.io' }) as Record<string, any>;

      assert.that(decodedToken.iss).is.equalTo('https://auth.thenativeweb.io');
      assert.that(decodedToken.sub).is.equalTo('jane.doe');
      assert.that(decodedToken['https://auth.thenativeweb.io/email']).is.equalTo('jane.doe@thenativeweb.io');
    });
  });

  suite('issueUntrustedToken', (): void => {
    test('returns a JWT.', async (): Promise<void> => {
      const { token, decodedToken } = Limes.issueUntrustedToken({
        issuer: 'https://untrusted.thenativeweb.io',
        subject: 'jane.doe'
      }) as {
        token: string;
        decodedToken: Record<string, any>;
      };

      assert.that(token).is.startingWith('ey');
      assert.that(decodedToken.iss).is.equalTo('https://untrusted.thenativeweb.io');
      assert.that(decodedToken.sub).is.equalTo('jane.doe');
    });

    test('returns a JWT with the given payload.', async (): Promise<void> => {
      const { token, decodedToken } = Limes.issueUntrustedToken({
        issuer: 'https://untrusted.thenativeweb.io',
        subject: 'jane.doe',
        payload: {
          'https://untrusted.thenativeweb.io/email': 'jane.doe@thenativeweb.io'
        }
      }) as {
        token: string;
        decodedToken: Record<string, any>;
      };

      assert.that(token).is.startingWith('ey');
      assert.that(decodedToken.iss).is.equalTo('https://untrusted.thenativeweb.io');
      assert.that(decodedToken.sub).is.equalTo('jane.doe');
      assert.that(decodedToken['https://untrusted.thenativeweb.io/email']).is.equalTo('jane.doe@thenativeweb.io');
    });
  });

  suite('verifyToken', (): void => {
    test('returns the decoded token if the token is valid.', async (): Promise<void> => {
      const token = limes.issueToken({
        issuer: 'https://auth.thenativeweb.io',
        subject: 'jane.doe'
      });

      const decodedToken = await limes.verifyToken({ token });

      assert.that(decodedToken.iss).is.equalTo('https://auth.thenativeweb.io');
      assert.that(decodedToken.sub).is.equalTo('jane.doe');
    });

    test('throws an error if the token is valid, but was issued by an unknown identity provider.', async (): Promise<void> => {
      const otherLimes = new Limes({
        identityProviders: [ identityProviderUnknown ]
      });

      const token = otherLimes.issueToken({
        issuer: 'https://auth.example.com',
        subject: 'jane.doe'
      });

      await assert.that(async (): Promise<void> => {
        await limes.verifyToken({ token });
      }).is.throwingAsync(`Issuer 'https://auth.example.com' not found.`);
    });

    test('throws an error if the token is not valid.', async (): Promise<void> => {
      await assert.that(async (): Promise<void> => {
        await limes.verifyToken({ token: 'invalidtoken' });
      }).is.throwingAsync('Failed to verify token.');
    });

    test('throws an error if the token contains invalid characters.', async (): Promise<void> => {
      await assert.that(async (): Promise<void> => {
        await limes.verifyToken({ token: 'invalid#token' });
      }).is.throwingAsync('Failed to verify token.');
    });
  });

  suite('verifyTokenMiddleware', (): void => {
    test('returns a function.', async (): Promise<void> => {
      const middleware = limes.verifyTokenMiddleware({
        issuerForAnonymousTokens: 'https://untrusted.thenativeweb.io'
      });

      assert.that(middleware).is.ofType('function');
    });

    suite('middleware', (): void => {
      let app: Express;

      setup(async (): Promise<void> => {
        app = express();

        app.use(limes.verifyTokenMiddleware({
          issuerForAnonymousTokens: 'https://untrusted.thenativeweb.io'
        }));

        app.get('/', (req, res): void => {
          res.json({ user: req.user, token: req.token });
        });
      });

      test('returns an anonymous token for non-authenticated requests.', async (): Promise<void> => {
        const { status, body } = await request(app).
          get('/').
          set('accept', 'application/json');

        assert.that(status).is.equalTo(200);
        assert.that(body.token as string).is.startingWith('ey');
        assert.that(body.user.id).is.equalTo('anonymous');
        assert.that(body.user.claims.sub).is.equalTo('anonymous');
        assert.that(body.user.claims.iss).is.equalTo('https://untrusted.thenativeweb.io');
        assert.that(body.user.claims['https://untrusted.thenativeweb.io/is-anonymous']).is.true();
      });

      test('returns an anonymous with the provided id for non-authenticated requests.', async (): Promise<void> => {
        const anonymousId = v4();
        const { status, body } = await request(app).
          get('/').
          set('accept', 'application/json').
          set('x-anonymous-id', anonymousId);

        assert.that(status).is.equalTo(200);
        assert.that(body.token as string).is.startingWith('ey');
        assert.that(body.user.id).is.equalTo(`anonymous-${anonymousId}`);
        assert.that(body.user.claims.sub).is.equalTo(`anonymous-${anonymousId}`);
        assert.that(body.user.claims.iss).is.equalTo('https://untrusted.thenativeweb.io');
        assert.that(body.user.claims['https://untrusted.thenativeweb.io/is-anonymous']).is.true();
      });

      test('returns an anonymous with the provided id sent using the query string for non-authenticated requests.', async (): Promise<void> => {
        const anonymousId = v4();
        const { status, body } = await request(app).
          get(`/?anonymousId=${anonymousId}`).
          set('accept', 'application/json');

        assert.that(status).is.equalTo(200);
        assert.that(body.token as string).is.startingWith('ey');
        assert.that(body.user.id).is.equalTo(`anonymous-${anonymousId}`);
        assert.that(body.user.claims.sub).is.equalTo(`anonymous-${anonymousId}`);
        assert.that(body.user.claims.iss).is.equalTo('https://untrusted.thenativeweb.io');
        assert.that(body.user.claims['https://untrusted.thenativeweb.io/is-anonymous']).is.true();
      });

      test('returns 401 for invalid tokens.', async (): Promise<void> => {
        const { status } = await request(app).
          get('/').
          set('accept', 'application/json').
          set('authorization', 'Bearer invalidtoken');

        assert.that(status).is.equalTo(401);
      });

      test('returns 401 for tokens with invalid characters.', async (): Promise<void> => {
        const { status } = await request(app).
          get('/').
          set('accept', 'application/json').
          set('authorization', 'Bearer invalid#token');

        assert.that(status).is.equalTo(401);
      });

      test('returns 401 for expired tokens.', async (): Promise<void> => {
        limes = new Limes({
          identityProviders: [ identityProviderExpired ]
        });

        const expiredToken = limes.issueToken({
          issuer: 'https://auth.thenativeweb.io',
          subject: 'jane.doe'
        });

        const { status } = await request(app).
          get('/').
          set('accept', 'application/json').
          set('authorization', `Bearer ${expiredToken}`);

        assert.that(status).is.equalTo(401);
      });

      test('returns 401 for tokens that were issued by an unknown identity provider.', async (): Promise<void> => {
        const otherLimes = new Limes({
          identityProviders: [ identityProviderUnknown ]
        });

        const token = otherLimes.issueToken({
          issuer: 'https://auth.example.com',
          subject: 'jane.doe'
        });

        const { status } = await request(app).
          get('/').
          set('accept', 'application/json').
          set('authorization', `Bearer ${token}`);

        assert.that(status).is.equalTo(401);
      });

      test('returns a decoded token for valid tokens.', async (): Promise<void> => {
        const token = limes.issueToken({
          issuer: 'https://auth.thenativeweb.io',
          subject: 'jane.doe'
        });

        const { status, body } = await request(app).
          get('/').
          set('accept', 'application/json').
          set('authorization', `Bearer ${token}`);

        assert.that(status).is.equalTo(200);
        assert.that(body.token).is.equalTo(token);
        assert.that(body.user.id).is.equalTo('jane.doe');
        assert.that(body.user.claims.sub).is.equalTo('jane.doe');
        assert.that(body.user.claims.iss).is.equalTo('https://auth.thenativeweb.io');
      });

      test('returns a decoded token for valid tokens sent using the query string.', async (): Promise<void> => {
        const token = limes.issueToken({
          issuer: 'https://auth.thenativeweb.io',
          subject: 'jane.doe'
        });

        const { status, body } = await request(app).
          get(`/?token=${token}`).
          set('accept', 'application/json');

        assert.that(status).is.equalTo(200);
        assert.that(body.token).is.equalTo(token);
        assert.that(body.user.id).is.equalTo('jane.doe');
        assert.that(body.user.claims.sub).is.equalTo('jane.doe');
        assert.that(body.user.claims.iss).is.equalTo('https://auth.thenativeweb.io');
      });
    });
  });
});
