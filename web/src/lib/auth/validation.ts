/**
 * Client-side auth form validation (email format + password strength).
 * Runs before any Firebase call so weak input never hits the network.
 */

export type PasswordStrength = "empty" | "weak" | "fair" | "good" | "strong";

export type FieldErrors = {
  email?: "invalidEmail";
  password?: "weakPassword" | "passwordRequired";
  confirmPassword?: "passwordMismatch";
};

const EMAIL_RE =
  /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

export function isValidEmail(email: string): boolean {
  const trimmed = email.trim();
  if (!trimmed || trimmed.length > 254) return false;
  return EMAIL_RE.test(trimmed);
}

export type PasswordChecks = {
  minLength: boolean;
  hasLower: boolean;
  hasUpper: boolean;
  hasDigit: boolean;
  hasSymbol: boolean;
};

export function getPasswordChecks(password: string): PasswordChecks {
  return {
    minLength: password.length >= 8,
    hasLower: /[a-z]/.test(password),
    hasUpper: /[A-Z]/.test(password),
    hasDigit: /\d/.test(password),
    hasSymbol: /[^A-Za-z0-9]/.test(password),
  };
}

/** True when password meets minimum complexity for signup. */
export function isPasswordStrongEnough(password: string): boolean {
  const c = getPasswordChecks(password);
  return c.minLength && c.hasLower && c.hasUpper && c.hasDigit;
}

export function getPasswordStrength(password: string): PasswordStrength {
  if (!password) return "empty";
  const c = getPasswordChecks(password);
  const score = [
    c.minLength,
    c.hasLower,
    c.hasUpper,
    c.hasDigit,
    c.hasSymbol,
  ].filter(Boolean).length;

  if (score <= 2) return "weak";
  if (score === 3) return "fair";
  if (score === 4) return "good";
  return "strong";
}

export function validateSignInFields(
  email: string,
  password: string,
): FieldErrors {
  const errors: FieldErrors = {};
  if (!isValidEmail(email)) {
    errors.email = "invalidEmail";
  }
  if (!password) {
    errors.password = "passwordRequired";
  }
  return errors;
}

export function validateSignUpFields(
  email: string,
  password: string,
  confirmPassword: string,
): FieldErrors {
  const errors: FieldErrors = {};
  if (!isValidEmail(email)) {
    errors.email = "invalidEmail";
  }
  if (!password || !isPasswordStrongEnough(password)) {
    errors.password = "weakPassword";
  }
  if (password !== confirmPassword) {
    errors.confirmPassword = "passwordMismatch";
  }
  return errors;
}

export function hasFieldErrors(errors: FieldErrors): boolean {
  return Boolean(errors.email || errors.password || errors.confirmPassword);
}
