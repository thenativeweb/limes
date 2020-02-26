# limes

limes authenticates users.

## Status

| Category         | Status                                                                                                  |
| ---------------- | ------------------------------------------------------------------------------------------------------- |
| Version          | [![npm](https://img.shields.io/npm/v/limes)](https://www.npmjs.com/package/limes)                       |
| Dependencies     | ![David](https://img.shields.io/david/thenativeweb/limes)                                               |
| Dev dependencies | ![David](https://img.shields.io/david/dev/thenativeweb/limes)                                           |
| Build            | ![GitHub Actions](https://github.com/thenativeweb/limes/workflows/Release/badge.svg?branch=master) |
| License          | ![GitHub](https://img.shields.io/github/license/thenativeweb/limes)                                     |

## Installation

```shell
$ npm install limes
```

## Quick start

First you need to add a reference to limes in your application:

```javascript
const { Limes, IdentityProvider } = require('limes');
```

If you use TypeScript, use the following code instead:

```typescript
import { Limes, IdentityProvider } from 'limes';
```

Now you need to create one or more identity providers. For each identity provider call the `IdentityProvider` constructor and hand over the `issuer` as well as a `privateKey` or a `certificate`, each in `.pem` format. Optionally, you may provide both:

```javascript
const identityProvider = new IdentityProvider({
  issuer: 'https://auth.thenativeweb.io',
  privateKey: await readFile(path.join(__dirname, 'privateKey.pem')),
  certificate: await readFile(path.join(__dirname, 'certificate.pem'))
});
```

_Please note that you have to specify the private key if you want to issue tokens and the certificate if you want to verify them._

Then you can call the `Limes` constructor function to create a new limes instance. Hand over an array of the previously created identity providers:

```javascript
const limes = new Limes({
  identityProviders: [ identityProvider ]
});
```

By default, tokens issues by an identity provider are valid for 24 hours. To use a custom expiration time, provide the `expiresInMinutes` option:

```javascript
const identityProvider = new IdentityProvider({
  issuer: 'https://auth.thenativeweb.io',
  privateKey: await readFile(path.join(__dirname, 'privateKey.pem')),
  certificate: await readFile(path.join(__dirname, 'certificate.pem')),
  expiresInMinutes: 60
});
```

### Issuing tokens

To issue a token call the `issueToken` function and provide the `issuer` and the `subject` you want to use as well as an optional payload:

```javascript
const token = limes.issueToken({
  issuer: 'https://auth.thenativeweb.io',
  subject: 'jane.doe',
  payload: {
    'https://auth.thenativeweb.io/email': 'jane.doe@thenativeweb.io'
  }
});
```

_Please note that the issuer must match one of the registered identity providers. Otherwise, `issueToken` will throw an error._

#### Issuing untrusted tokens for testing

From time to time, e.g. for testing, you may want to get a JSON object that looks like a decoded token, but avoid the effort to create a signed token first. For this, use the static `issueUntrustedToken` function and hand over the desired `issuer`, the `subject`, and an optional `payload`:

```javascript
const { token, decodedToken } = Limes.issueUntrustedToken({
  issuer: 'https://untrusted.thenativeweb.io',
  subject: 'jane.doe'
});
```

_Please note that this is highly insecure, and should never be used for production code!_

### Verifying tokens

To verify a token call the `verifyToken` function and provide the token. This function tries to verify and decode the token using the identity provider that matches the token's `iss` value and returns the decoded token:

```javascript
const decodedToken = await limes.verifyToken({ token });
```

If no identity provider for the token's `iss` value is found, an exception is thrown. Also, an exception is thrown if the token is invalid.

### Using middleware

To verify tokens in web applications, there is a middleware for Express. To use it call the `verifyTokenMiddleware` function and hand over a made-up issuer value you want to use for anonymous tokens:

```javascript
app.use(limes.verifyTokenMiddleware({
  issuerForAnonymousTokens: 'https://anonymous.thenativeweb.io'
}));
```

_Please note that the issuer for anonymous tokens is made-up, and does not provide any security. It's just a string that is used without further validation._

The middleware expects the token to be inside the `authorization` HTTP header, prefixed with the term `Bearer`:

    authorization: Bearer <token>

Alternatively, you may transfer the token using the query string parameter `token`:

    GET /foo/bar?token=<token>

Either way, the verified and decoded token will be attached to the `req.user` property, while the original token will be attached to the `req.token` property:

```javascript
const app = express();

app.use(limes.verifyTokenMiddleware({
  issuerForAnonymousTokens: 'https://anonymous.thenativeweb.io'
}));

app.get('/', (req, res) => {
  res.json({ user: req.user, token: req.token });
});
```

If a request does have an invalid token, an expired one, or one from an unknown issuer, the middleware returns the status code `401`.

### Handling anonymous users

If a request does not provide a token, a token for an anonymous user will be issued. This issued token uses `anonymous` for the `sub` property, and the aforementioned issuer for anonymous tokens. Anonymous tokens have an additional claim `<issuerForAnonymousTokens>/is-anonymous` set to `true`.

_Please make sure that your application code handles anonymous users in an intended way! The middleware does not block anonymous users, it just identifies and marks them!_

To differ between multiple anonymous users, your client can send a uuid using the `X-Anonymous-Id` header:

    X-Anonymous-Id: <uuid>

Alternatively, you may pass the uuid via the query string parameter `anonymousId`:

    GET /foo/bar?anonymousId=<uuid>

This issued token uses `anonymous-<uuid>` for the `sub` property.

If both a token and an anonymous id are provided, the anonymous id is ignored.

## Using it for websockets

To authenticate websockets requests, call `verifyTokenInWebsocketUpgradeRequest`.

```javascript
server.on('upgrade', async (request, socket, head) => {
  const result = await limes.verifyTokenInWebsocketUpgradeRequest({
    issuerForAnonymousTokens: 'https://anonymous.thenativeweb.io',
    upgradeRequest: request
  })
  
  ws.handleUpgrade(request, socket, head, () => {
    // ...
  });
})
```

## Running the build

```shell
$ npx roboter
```
