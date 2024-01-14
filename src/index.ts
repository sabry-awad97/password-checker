export interface PasswordCheckResult {
  password: string;
  status: "Compromised" | "Safe";
  score?: number;
}

export class PasswordChecker {
  public static hashPassword(password: string): string {
    const hash = new Bun.CryptoHasher("sha1");
    hash.update(password);
    return hash.digest("hex").toUpperCase();
  }
}
