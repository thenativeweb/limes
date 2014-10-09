# limes

limes authenticates users.

## Installation

    $ npm install limes

## Quick start

First you need to add a reference to limes in your application.

```javascript
var Limes = require('limes');
```

Then you can call the `Limes` constructor function to create a new limes instance. You need to specify a parameter object with the `identityProviderName` and either a `privateKey` or a `certificate`, each in `.pem` format. Optionally, you may also provide both.

```javascript
var limes = new Limes({
  identityProviderName: 'auth.example.com',
  privateKey: fs.readFileSync(path.join(__dirname, 'privateKey.pem')),
  certificate: fs.readFileSync(path.join(__dirname, 'certificate.pem'))
});
```

Please note that you have to specify the private key if you want to issue tokens and the certificate if you want to verify them.

### Issuing tokens

To issue a token call the `issueTokenFor` function and provide the subject you want to issue the token for as well as the desired payload.

```javascript
var token = limes.issueTokenFor('Jane Doe', {
  foo: 'bar'
});
```

### Verifying tokens

To verify a token call the `verifyToken` function and provide the token and a callback. As a result, it returns the decoded token.

```javascript
limes.verifyToken(token, function (err, decodedToken) {
  // ...
});
```

### Using middleware

To verify tokens there are also middlewares for Express and Socket.io. To use them call the `verifyTokenMiddlewareExpress` or `verifyTokenMiddlewareSocketIo` functions and optionally specify the payload for non-authenticated users.

```javascript
app.use(limes.verifyTokenMiddlewareExpress({
  payloadWhenAnonymous: {
    foo: 'bar'
  }
}));

io.use(limes.verifyTokenMiddlewareSocketIo({
  payloadWhenAnonymous: {
    foo: 'bar'
  }
}));
```

If a request does not provide a token, an anonymous token is issued. If a request does have an invalid token, an expired one, or one with a wrong issuer, the middleware returns a `401` respectively an error.

Otherwise, it attaches the decoded token to `req.user` respectively `socket.user`.

The Express middleware expects the token to be inside an HTTP header called `authorization` and prefixed with the term `Bearer`.

    authorization: Bearer <token>

The Socket.io middleware expects you to emit an `authenticate` event and provide the token as well as a callback.

```javascript
socket.emit('authenticate', token, function (err) {
  // ...
});
```

## Running the build

This module can be built using [Grunt](http://gruntjs.com/). Besides running the tests, this also analyses the code. To run Grunt, go to the folder where you have installed limes and run `grunt`. You need to have [grunt-cli](https://github.com/gruntjs/grunt-cli) installed.

    $ grunt

## License

The MIT License (MIT)
Copyright (c) 2014 the native web.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
