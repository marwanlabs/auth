export class AuthServerError extends Error {
  readonly status: number;
  readonly code: string | undefined;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = "AuthServerError";
    this.status = status;
    this.code = code;
  }
}
