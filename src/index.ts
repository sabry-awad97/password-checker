import { Bar, MultiBar, Presets } from "cli-progress";
import { program } from "commander";
import pLimit from "p-limit";

export interface PasswordCheckResult {
  password: string;
  status: "Compromised" | "Safe";
  count: number;
}

const batchItems = <T>(items: T[], batchSize: number): T[][] => {
  return Array.from(
    { length: Math.ceil(items.length / batchSize) },
    (_, index) => items.slice(index * batchSize, (index + 1) * batchSize)
  );
};

export class PwnedApi {
  async fetchData(prefix: string): Promise<string[]> {
    const requestUrl = `https://api.pwnedpasswords.com/range/${prefix}`;
    const response = await fetch(requestUrl);
    const data = await response.text();
    return data.split("\r\n");
  }
}

export class Sha1Hasher {
  hash(password: string): string {
    const hash = new Bun.CryptoHasher("sha1");
    hash.update(password);
    return hash.digest("hex").toUpperCase();
  }
}

export class PasswordChecker {
  constructor(private hasher: Sha1Hasher, private passwordApi: PwnedApi) {}

  public async checkPassword(password: string): Promise<PasswordCheckResult> {
    const passwordHash = this.hasher.hash(password);
    const prefix = passwordHash.slice(0, 5);
    const suffix = passwordHash.slice(5);
    const dataLines = await this.passwordApi.fetchData(prefix);

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

  async checkPasswords(passwords: string[]): Promise<PasswordCheckResult[]> {
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

    const batchedPasswords: string[][] = batchItems(passwords, batchSize);

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
  .action(async (passwords: string[], options) => {
    const hasher = new Sha1Hasher();
    const passwordApi = new PwnedApi();
    const passwordChecker = new PasswordChecker(hasher, passwordApi);

    const results = await passwordChecker.checkPasswords(passwords);

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

if (import.meta.path === Bun.main) {
  program.parse(Bun.argv);

  if (!Bun.argv.slice(2).length) {
    program.outputHelp();
  }
}
