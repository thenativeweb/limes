const minutesPerDay = 24 * 60;

type TAlgorithm = "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512";

class IdentityProvider {
  public issuer: string;

  public privateKey?: Buffer;

  public certificate?: Buffer;

  public algorithm: TAlgorithm;

  public expiresInMinutes: number;

  public constructor ({
    issuer,
    privateKey,
    certificate,
    algorithm = 'RS256',
    expiresInMinutes = minutesPerDay
  }: {
    issuer: string;
    privateKey?: Buffer;
    certificate?: Buffer;
    algorithm?: TAlgorithm;
    expiresInMinutes?: number;
  }) {
    this.issuer = issuer;
    this.privateKey = privateKey;
    this.certificate = certificate;
    this.algorithm = algorithm;
    this.expiresInMinutes = expiresInMinutes;
  }
}

export { IdentityProvider };
