import assert from 'assertthat';
import fs from 'fs';
import IdentityProvider from '../../lib/IdentityProvider';
import path from 'path';

/* eslint-disable no-sync */
const certificate = fs.readFileSync(path.join(__dirname, '..', 'shared', 'keys', 'auth.thenativeweb.io', 'certificate.pem')),
      privateKey = fs.readFileSync(path.join(__dirname, '..', 'shared', 'keys', 'auth.thenativeweb.io', 'privateKey.pem'));
/* eslint-enable no-sync */

suite('IdentityProvider', (): void => {
  test('is a function.', async (): Promise<void> => {
    assert.that(IdentityProvider).is.ofType('function');
  });

  test('constructs an IdentityProvider.', async (): Promise<void> => {
    const identityProvider = new IdentityProvider({
      issuer: 'https://auth.thenativeweb.io/',
      privateKey,
      certificate
    });

    assert.that(identityProvider).is.atLeast({
      issuer: 'https://auth.thenativeweb.io/',
      privateKey,
      certificate
    });
  });
});
