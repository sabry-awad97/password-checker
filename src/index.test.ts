import { describe, expect, it } from "bun:test";

import { PasswordChecker, type PasswordCheckResult } from ".";

describe("PasswordChecker", () => {
  describe("hashPassword", () => {
    it("should correctly hash a password using SHA-1", () => {
      // Arrange
      const password = "password";

      // Act
      const hashedPassword = PasswordChecker.hashPassword(password);
      const expectedHash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";

      // Assert
      expect(hashedPassword).toBe(expectedHash);
    });
  });

  describe("checkPassword", () => {
    it('should return "Compromised" status for a known compromised password', async () => {
      // Replace this with a known compromised password
      const compromisedPassword = "password123";

      const result = await PasswordChecker.checkPassword(compromisedPassword);

      expect(result.password).toBe(compromisedPassword);
      expect(result.status).toBe("Compromised");
    });

    it('should return "Safe" status for a known safe password', async () => {
      // Replace this with a known safe password
      const safePassword = "5ecureP@ssw0rd";

      const result: PasswordCheckResult = await PasswordChecker.checkPassword(
        safePassword
      );

      expect(result.password).toBe(safePassword);
      expect(result.status).toBe("Safe");
    });
  });
});
