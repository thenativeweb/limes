// The types of the single claims have been taken from the RFC that can be found
// at: https://tools.ietf.org/html/rfc7519#section-4.1
export type Claims = Record<string, any> & {
  sub: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
};
