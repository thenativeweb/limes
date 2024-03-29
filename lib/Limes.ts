import { Claims } from './Claims';
import { flaschenpost } from 'flaschenpost';
import { IdentityProvider } from './IdentityProvider';
import jwt from 'jsonwebtoken';
import { RequestHandler } from 'express';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    export interface Request {
      token?: string;
      user?: {
        id: string;
        claims: Claims;
      };
    }
  }
}

class Limes {
  public identityProviders: IdentityProvider[];

  private readonly logger = flaschenpost.getLogger();

  public constructor ({ identityProviders }: {
    identityProviders: IdentityProvider[];
  }) {
    this.identityProviders = identityProviders;
  }

  public static issueUntrustedToken ({ issuer, subject, payload = {}}: {
    issuer: string;
    subject: string;
    payload?: Record<string, any>;
  }): {
      token: string;
      decodedToken: null | Claims;
    } {
    const expiresInMinutes = 60;

    const token = jwt.sign(payload, 'secret-irrelevant-for-none-algorithm', {
      algorithm: 'none',
      subject,
      issuer,
      expiresIn: expiresInMinutes * 60
    });

    const decodedToken = jwt.decode(token);

    if (!decodedToken) {
      throw new Error('Token decoding failed.');
    }
    if (typeof decodedToken === 'string') {
      throw new Error('Token payload malformed.');
    }
    if (!decodedToken.sub) {
      throw new Error('Token payload malformed.');
    }

    return { token, decodedToken: { ...decodedToken, sub: decodedToken.sub }};
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
    payload?: Record<string, any>;
  }): string {
    const identityProvider = this.getIdentityProviderByIssuer({ issuer });

    if (!identityProvider.privateKey) {
      throw new Error('Private key is missing.');
    }

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
  }): Promise<Claims> {
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

    if (!untrustedDecodedToken.iss) {
      throw new Error('Issuer missing.');
    }

    const identityProvider = this.getIdentityProviderByIssuer({
      issuer: untrustedDecodedToken.iss
    });

    const decodedToken: Claims = await new Promise((resolve, reject): void => {
      try {
        if (!identityProvider.certificate) {
          throw new Error('Certificate is missing.');
        }

        jwt.verify(
          token,
          identityProvider.certificate,
          {
            algorithms: [ 'RS256' ],
            issuer: identityProvider.issuer
          },
          (err, verifiedToken): void => {
            if (err) {
              this.logger.error(err.message);

              return reject(new Error('Failed to verify token.'));
            }

            if (typeof verifiedToken === 'string') {
              return reject(new Error('Token payload malformed.'));
            }

            if (!verifiedToken) {
              return reject(new Error('Token could not be decoded.'));
            }

            if (!verifiedToken.sub) {
              return reject(new Error('Token payload does not contain sub.'));
            }

            resolve({
              ...verifiedToken,
              sub: verifiedToken.sub
            });
          }
        );
      } catch (ex: unknown) {
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

      if (typeof authorizationQuery !== 'string' && typeof authorizationQuery !== 'undefined') {
        res.status(400).end();

        return;
      }

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
        } catch (ex: unknown) {
          if (ex instanceof Error) {
            this.logger.error(ex.message);
          }

          res.status(401).end();

          return;
        }
      } else {
        const payload = {
          [`${issuerForAnonymousTokens}/is-anonymous`]: true
        };

        let subject = 'anonymous';

        const { anonymousId } = req.query;

        if (req.headers['x-anonymous-id']) {
          subject += `-${req.headers['x-anonymous-id']}`;
        } else if (anonymousId) {
          if (typeof anonymousId !== 'string') {
            res.status(400).end();

            return;
          }

          subject += `-${anonymousId}`;
        }

        ({ token, decodedToken } = Limes.issueUntrustedToken({
          issuer: issuerForAnonymousTokens,
          subject,
          payload
        }));
      }

      if (!decodedToken) {
        this.logger.error('Failed to verify token.');

        res.status(400).end();

        return;
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

export {
  Limes,
  Claims,
  IdentityProvider
};
