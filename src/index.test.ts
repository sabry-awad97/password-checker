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
});
