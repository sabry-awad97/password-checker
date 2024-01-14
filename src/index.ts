export interface PasswordCheckResult {
  password: string;
  status: "Compromised" | "Safe";
}

export class PasswordChecker {
  public static hashPassword(password: string): string {
    const hash = new Bun.CryptoHasher("sha1");
    hash.update(password);
    return hash.digest("hex").toUpperCase();
  }

  public static async checkPassword(
    password: string
  ): Promise<PasswordCheckResult> {
    const passwordHash = this.hashPassword(password);
    const prefix = passwordHash.slice(0, 5);
    const suffix = passwordHash.slice(5);
    const requestUrl = `https://api.pwnedpasswords.com/range/${prefix}`;
    const response = await fetch(requestUrl);
    const data = await response.text();
    const dataLines = data.split("\r\n");

    let compromisedCount = 0;
    for (const line of dataLines) {
      if (line.startsWith(suffix)) {
        compromisedCount += parseInt(line.split(":")[1], 10) || 0;
      }
    }

    return {
      password,
      status: compromisedCount > 0 ? "Compromised" : "Safe",
    };
  }
}
