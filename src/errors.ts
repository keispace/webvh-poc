export class AppError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export function asErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
