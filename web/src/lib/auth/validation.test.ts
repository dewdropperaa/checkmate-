import { describe, expect, it } from "vitest";
import {
  getPasswordStrength,
  hasFieldErrors,
  isPasswordStrongEnough,
  isValidEmail,
  validateSignInFields,
  validateSignUpFields,
} from "@/lib/auth/validation";

describe("isValidEmail", () => {
  it("accepts normal addresses", () => {
    expect(isValidEmail("user@example.com")).toBe(true);
  });

  it("rejects malformed addresses", () => {
    expect(isValidEmail("not-an-email")).toBe(false);
    expect(isValidEmail("a@b")).toBe(false);
    expect(isValidEmail("")).toBe(false);
  });
});

describe("password strength", () => {
  it("requires length + upper + lower + digit", () => {
    expect(isPasswordStrongEnough("short")).toBe(false);
    expect(isPasswordStrongEnough("alllowercase1")).toBe(false);
    expect(isPasswordStrongEnough("ALLUPPERCASE1")).toBe(false);
    expect(isPasswordStrongEnough("NoDigitsHere")).toBe(false);
    expect(isPasswordStrongEnough("GoodPass1")).toBe(true);
  });

  it("maps strength levels", () => {
    expect(getPasswordStrength("")).toBe("empty");
    expect(getPasswordStrength("abc")).toBe("weak");
    expect(getPasswordStrength("GoodPass1!")).toBe("strong");
  });
});

describe("validateSignUpFields", () => {
  it("blocks invalid email before submit", () => {
    const errors = validateSignUpFields("bad", "GoodPass1", "GoodPass1");
    expect(errors.email).toBe("invalidEmail");
    expect(hasFieldErrors(errors)).toBe(true);
  });

  it("blocks weak password before submit", () => {
    const errors = validateSignUpFields("a@b.co", "weak", "weak");
    expect(errors.password).toBe("weakPassword");
  });

  it("blocks mismatched confirm password before submit", () => {
    const errors = validateSignUpFields(
      "a@b.co",
      "GoodPass1",
      "GoodPass2",
    );
    expect(errors.confirmPassword).toBe("passwordMismatch");
  });

  it("passes when all fields are valid", () => {
    const errors = validateSignUpFields(
      "a@b.co",
      "GoodPass1",
      "GoodPass1",
      true,
    );
    expect(hasFieldErrors(errors)).toBe(false);
  });

  it("requires terms acceptance", () => {
    const errors = validateSignUpFields(
      "a@b.co",
      "GoodPass1",
      "GoodPass1",
      false,
    );
    expect(errors.terms).toBe("agreeRequired");
    expect(hasFieldErrors(errors)).toBe(true);
  });
});

describe("validateSignInFields", () => {
  it("requires password", () => {
    const errors = validateSignInFields("a@b.co", "");
    expect(errors.password).toBe("passwordRequired");
  });
});
