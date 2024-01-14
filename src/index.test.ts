import { beforeEach, describe, expect, it } from "bun:test";

import {
  PasswordChecker,
  PwnedApi,
  Sha1Hasher,
  type PasswordCheckResult,
} from ".";

describe("Hasher", () => {
  describe("Hash", () => {
    it("should correctly hash a password using SHA-1", () => {
      // Arrange
      const password = "password";

      // Act
      const hasher = new Sha1Hasher();

      const hashedPassword = hasher.hash(password);
      const expectedHash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";

      // Assert
      expect(hashedPassword).toBe(expectedHash);
    });
  });
});

describe("PasswordChecker", () => {
  let passwordChecker: PasswordChecker;

  beforeEach(() => {
    const hasher = new Sha1Hasher();
    const passwordApi = new PwnedApi();
    passwordChecker = new PasswordChecker(hasher, passwordApi);
  });

  describe("checkPassword", () => {
    it('should return "Compromised" status for a known compromised password', async () => {
      // Replace this with a known compromised password
      const compromisedPassword = "password123";

      const hasher = new Sha1Hasher();
      const passwordApi = new PwnedApi();
      const passwordChecker = new PasswordChecker(hasher, passwordApi);

      const result = await passwordChecker.checkPassword(compromisedPassword);

      expect(result.password).toBe(compromisedPassword);
      expect(result.status).toBe("Compromised");
    });

    it('should return "Safe" status for a known safe password', async () => {
      // Replace this with a known safe password
      const safePassword = "5ecureP@ssw0rd";

      const result: PasswordCheckResult = await passwordChecker.checkPassword(
        safePassword
      );

      expect(result.password).toBe(safePassword);
      expect(result.status).toBe("Safe");
    });
  });
});
