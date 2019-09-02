import IdentityProvider from './IdentityProvider';
import { RequestHandler } from 'express-serve-static-core';
import jwt, { VerifyErrors } from 'jsonwebtoken';

declare global {
  /* eslint-disable @typescript-eslint/no-namespace */
  namespace Express {
    export interface Request {
      token?: string;
      user?: {
        id: string;
        claims: object | string;
      };
    }
  }
  /* eslint-enable @typescript-eslint/no-namespace */
}

class Limes {
  /* eslint-disable @typescript-eslint/member-naming */
  public static IdentityProvider = IdentityProvider;
  /* eslint-enable @typescript-eslint/member-naming */

  public identityProviders: IdentityProvider[];

  public constructor ({ identityProviders }: {
    identityProviders: IdentityProvider[];
  }) {
    if (identityProviders.length === 0) {
      throw new Error('Identity providers are missing.');
    }

    this.identityProviders = identityProviders;
  }

  public static issueUntrustedToken ({ issuer, subject, payload = {}}: {
    issuer: string;
    subject: string;
    payload?: object;
  }): {
      token: string;
      decodedToken: null | { [key: string]: any };
    } {
    const expiresInMinutes = 60;

    const token = jwt.sign(payload, 'secret-irrelevant-for-none-algorithm', {
      algorithm: 'none',
      subject,
      issuer,
      expiresIn: expiresInMinutes * 60
    });

    const decodedToken = jwt.decode(token);

    if (typeof decodedToken === 'string') {
      throw new Error('Token payload malformed.');
    }

    return { token, decodedToken };
  }

  public getIdentityProviderByIssuer ({ issuer }: {
    issuer: string;
  }): IdentityProvider {
    const requestedIdentityProvider = this.identityProviders.find(
      (identityProvider: IdentityProvider): boolean => identityProvider.issuer === issuer
    );

    if (!requestedIdentityProvider) {
      throw new Error(`Issuer '${issuer}' not found.`);
    }

    return requestedIdentityProvider;
  }

  public issueToken ({ issuer, subject, payload = {}}: {
    issuer: string;
    subject: string;
    payload?: object;
  }): string {
    const identityProvider = this.getIdentityProviderByIssuer({ issuer });

    const token = jwt.sign(payload, identityProvider.privateKey, {
      algorithm: 'RS256',
      subject,
      issuer: identityProvider.issuer,
      expiresIn: identityProvider.expiresInMinutes * 60
    });

    return token;
  }

  public async verifyToken ({ token }: {
    token: string;
  }): Promise<{ [key: string]: any | undefined }> {
    let untrustedDecodedToken;

    try {
      untrustedDecodedToken = jwt.decode(token);
    } catch {
      throw new Error('Failed to verify token.');
    }

    if (!untrustedDecodedToken) {
      throw new Error('Failed to verify token.');
    }

    if (typeof untrustedDecodedToken === 'string') {
      throw new Error('Token payload malformed.');
    }

    const identityProvider = this.getIdentityProviderByIssuer({
      issuer: untrustedDecodedToken.iss
    });

    const decodedToken = await new Promise((resolve: (value?: { [key: string]: any | undefined }) => void, reject: (reason?: any) => void): void => {
      try {
        jwt.verify(
          token,
          identityProvider.certificate,
          {
            algorithms: [ 'RS256' ],
            issuer: identityProvider.issuer
          },
          (err: VerifyErrors, verifiedToken: { [key: string]: any | undefined } | string): void => {
            if (err) {
              return reject(new Error('Failed to verify token.'));
            }

            if (typeof verifiedToken === 'string') {
              throw new Error('Token payload malformed.');
            }

            resolve(verifiedToken);
          }
        );
      } catch (ex) {
        reject(ex);
      }
    });

    return decodedToken;
  }

  public verifyTokenMiddleware ({ issuerForAnonymousTokens }: {
    issuerForAnonymousTokens: string;
  }): RequestHandler {
    return async (req, res, next): Promise<void> => {
      let token;

      const authorizationHeader = req.headers.authorization,
            authorizationQuery = req.query.token;

      if (authorizationHeader) {
        const [ authorizationType, authorizationValue ] = authorizationHeader.split(' ');

        if (authorizationType === 'Bearer') {
          token = authorizationValue;
        }
      } else if (authorizationQuery) {
        token = authorizationQuery;
      }

      let decodedToken;

      if (token) {
        try {
          decodedToken = await this.verifyToken({ token });
        } catch {
          return res.status(401).end();
        }
      } else {
        ({ token, decodedToken } = Limes.issueUntrustedToken({
          issuer: issuerForAnonymousTokens,
          subject: 'anonymous'
        }));
      }

      if (!decodedToken) {
        return res.status(400).end();
      }

      /* eslint-disable no-param-reassign */
      req.token = token;
      req.user = {
        id: decodedToken.sub,
        claims: decodedToken
      };
      /* eslint-enable no-param-reassign */

      next();
    };
  }
}

export default Limes;
