const minutesPerDay = 24 * 60;

class IdentityProvider {
  public issuer: string;

  public privateKey?: Buffer;

  public certificate?: Buffer;

  public expiresInMinutes: number;

  public constructor ({
    issuer,
    privateKey,
    certificate,
    expiresInMinutes = minutesPerDay
  }: {
    issuer: string;
    privateKey?: Buffer;
    certificate?: Buffer;
    expiresInMinutes?: number;
  }) {
    this.issuer = issuer;
    this.privateKey = privateKey;
    this.certificate = certificate;
    this.expiresInMinutes = expiresInMinutes;
  }
}

export default IdentityProvider;
