/**
 * Minimal JWT payload shape expected after verifying either:
 * - a backend‑issued access token, or
 * - a Firebase ID token (normalized by the auth middleware).
 */
export interface JWTUser {
    id: string;
    email: string;
    iat?: number;
    exp?: number;
  }