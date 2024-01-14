import { MultiBar, Presets } from "cli-progress";
import { program } from "commander";
import pLimit from "p-limit";

export interface PasswordCheckResult {
  password: string;
  status: "Compromised" | "Safe";
  count: number;
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
      count: compromisedCount,
    };
  }

  static async checkPasswords(
    passwords: string[]
  ): Promise<PasswordCheckResult[]> {
    const multiBar = new MultiBar(
      {
        format:
          "{bar} | {percentage}% | ETA: {eta}s | {value}/{total} passwords",
        hideCursor: true,
      },
      Presets.shades_classic
    );

    const limit = pLimit(5);

    const batchSize = 5;

    const batchedPasswords: string[][] = [];
    for (let i = 0; i < passwords.length; i += batchSize) {
      batchedPasswords.push(passwords.slice(i, i + batchSize));
    }

    const batchPromises = batchedPasswords.map((batch) => {
      const bar = multiBar.create(batch.length, 0);
      const promises = batch.map((password) =>
        limit(async () => {
          const result = await this.checkPassword(password);
          bar.increment();
          return result;
        })
      );
      return Promise.all(promises);
    });

    const batchResults = await Promise.all(batchPromises);

    multiBar.stop();

    const results: PasswordCheckResult[] = batchResults.flat();
    return results;
  }
}

program
  .version("1.0.0")
  .description(
    "Checks whether passwords have been compromised in data breaches."
  );

program
  .command("check <passwords...>")
  .option(
    "-l, --local <file>",
    "Path to a local compromised password database file"
  )
  .option("-s, --strength", "Check password strength")
  .description("Check the provided passwords")
  .action(async (passwords: string[], options) => {
    const results = await PasswordChecker.checkPasswords(passwords);

    for (const result of results) {
      if (result.status === "Compromised") {
        console.log(
          `The password '${result.password}' was found in ${result.count} data breaches. Please consider using a different password.`
        );
      } else {
        console.log(
          `The password '${result.password}' has not been found in any known data breaches. Good job!`
        );
      }
    }
  });

program.parse(Bun.argv);

if (!Bun.argv.slice(2).length) {
  program.outputHelp();
}
