"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import type { User } from "firebase/auth";
import { Link } from "@/i18n/navigation";
import {
  ApiError,
  listOrgSites,
  removeSiteCredentials,
  saveSiteCredentials,
  type BackendUser,
  type OrgSite,
} from "@/lib/api";
import { canUseAuthenticatedScanning } from "@/lib/quota";
import styles from "./dashboard.module.css";

type Props = {
  currentUser: User;
  backendUser: BackendUser;
  refreshKey?: number;
};

export function SiteAuthPanel({
  currentUser,
  backendUser,
  refreshKey = 0,
}: Props) {
  const t = useTranslations("dashboard");
  const feature = canUseAuthenticatedScanning(backendUser);
  const locked = !feature.allowed;

  const [sites, setSites] = useState<OrgSite[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string>("");
  const [loginUrl, setLoginUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [usernameField, setUsernameField] = useState("username");
  const [passwordField, setPasswordField] = useState("password");
  const [excludedPaths, setExcludedPaths] = useState("");
  const [consent, setConsent] = useState(false);
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const loadSites = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = await currentUser.getIdToken();
      const data = await listOrgSites(token);
      const active = data.sites.filter((s) => s.active);
      setSites(active);
      setSelectedId((prev) => {
        if (prev && active.some((s) => s.id === prev)) return prev;
        return active[0]?.id ?? "";
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("authScan.loadError"));
    } finally {
      setLoading(false);
    }
  }, [currentUser, t]);

  useEffect(() => {
    void loadSites();
  }, [loadSites, refreshKey]);

  const selected = sites.find((s) => s.id === selectedId) ?? null;

  useEffect(() => {
    if (!selected) return;
    const auth = selected.authenticated_scanning;
    setLoginUrl(auth.login_url ?? "");
    setUsernameField(auth.username_field ?? "username");
    setPasswordField(auth.password_field ?? "password");
    setExcludedPaths((auth.excluded_paths ?? []).join("\n"));
    setUsername("");
    setPassword("");
    setConsent(false);
    setMessage(null);
  }, [selected]);

  async function onSave(event: FormEvent) {
    event.preventDefault();
    if (!selected || locked || !consent) return;
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      const token = await currentUser.getIdToken();
      await saveSiteCredentials(token, selected.id, {
        login_url: loginUrl.trim(),
        username: username.trim(),
        password,
        username_field: usernameField.trim() || "username",
        password_field: passwordField.trim() || "password",
        excluded_paths: excludedPaths
          .split(/[\n,]/)
          .map((p) => p.trim())
          .filter(Boolean),
        credentials_authorized: true,
      });
      setMessage(t("authScan.saved"));
      setPassword("");
      setConsent(false);
      await loadSites();
    } catch (cause) {
      if (cause instanceof ApiError) {
        setError(cause.message);
      } else {
        setError(cause instanceof Error ? cause.message : t("authScan.saveError"));
      }
    } finally {
      setSaving(false);
    }
  }

  async function onRemove() {
    if (!selected) return;
    setRemoving(true);
    setError(null);
    setMessage(null);
    try {
      const token = await currentUser.getIdToken();
      await removeSiteCredentials(token, selected.id);
      setMessage(t("authScan.removed"));
      setLoginUrl("");
      setUsername("");
      setPassword("");
      setExcludedPaths("");
      await loadSites();
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : t("authScan.removeError"),
      );
    } finally {
      setRemoving(false);
    }
  }

  return (
    <section className={styles.panel} aria-labelledby="auth-scan-title">
      <div className={styles.panelHeading}>
        <div>
          <h2 id="auth-scan-title" className={styles.panelTitle}>
            {t("authScan.title")}
          </h2>
          <p className={styles.panelDescription}>{t("authScan.help")}</p>
        </div>
        {locked ? (
          <span className={styles.statusBadge}>{t("authScan.lockedBadge")}</span>
        ) : null}
      </div>

      {locked ? (
        <p className={styles.warning} role="status">
          [ {t("authScan.locked")}{" "}
          <Link href="/#pricing">{t("quota.pricingLink")}</Link> ]
        </p>
      ) : null}

      {loading ? <p className={styles.formHint}>{t("authScan.loading")}</p> : null}
      {!loading && sites.length === 0 ? (
        <p className={styles.formHint}>{t("authScan.noSites")}</p>
      ) : null}

      {sites.length > 0 ? (
        <form
          onSubmit={(event) => void onSave(event)}
          className={locked ? styles.authScanLocked : undefined}
          aria-disabled={locked}
        >
          <label className={styles.fieldLabel} htmlFor="auth-site">
            {t("authScan.siteLabel")}
          </label>
          <select
            id="auth-site"
            className={styles.input}
            value={selectedId}
            onChange={(event) => setSelectedId(event.target.value)}
            disabled={locked}
          >
            {sites.map((site) => (
              <option key={site.id} value={site.id}>
                {site.target}
                {site.authenticated_scanning.configured
                  ? ` (${t("authScan.configured")})`
                  : ""}
              </option>
            ))}
          </select>

          <div className={styles.authWarning} role="note">
            <strong>{t("authScan.testAccountTitle")}</strong>
            <p>{t("authScan.testAccountBody")}</p>
          </div>

          <label className={styles.fieldLabel} htmlFor="auth-login-url">
            {t("authScan.loginUrl")}
          </label>
          <input
            id="auth-login-url"
            className={styles.input}
            type="url"
            value={loginUrl}
            onChange={(event) => setLoginUrl(event.target.value)}
            placeholder="https://example.com/login"
            required={!locked}
            disabled={locked}
          />

          <div className={styles.authGrid}>
            <div>
              <label className={styles.fieldLabel} htmlFor="auth-username">
                {t("authScan.username")}
              </label>
              <input
                id="auth-username"
                className={styles.input}
                type="text"
                autoComplete="off"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder={
                  selected?.authenticated_scanning.username_hint ??
                  t("authScan.usernamePlaceholder")
                }
                required={!locked}
                disabled={locked}
              />
            </div>
            <div>
              <label className={styles.fieldLabel} htmlFor="auth-password">
                {t("authScan.password")}
              </label>
              <input
                id="auth-password"
                className={styles.input}
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required={!locked}
                disabled={locked}
              />
            </div>
          </div>

          <div className={styles.authGrid}>
            <div>
              <label className={styles.fieldLabel} htmlFor="auth-user-field">
                {t("authScan.usernameField")}
              </label>
              <input
                id="auth-user-field"
                className={styles.input}
                type="text"
                value={usernameField}
                onChange={(event) => setUsernameField(event.target.value)}
                disabled={locked}
              />
              <p className={styles.formHint}>{t("authScan.fieldNameHelp")}</p>
            </div>
            <div>
              <label className={styles.fieldLabel} htmlFor="auth-pass-field">
                {t("authScan.passwordField")}
              </label>
              <input
                id="auth-pass-field"
                className={styles.input}
                type="text"
                value={passwordField}
                onChange={(event) => setPasswordField(event.target.value)}
                disabled={locked}
              />
            </div>
          </div>

          <label className={styles.fieldLabel} htmlFor="auth-excluded">
            {t("authScan.excludedPaths")}
          </label>
          <textarea
            id="auth-excluded"
            className={styles.textarea}
            rows={3}
            value={excludedPaths}
            onChange={(event) => setExcludedPaths(event.target.value)}
            placeholder={"/delete-account\n/cancel-subscription"}
            disabled={locked}
          />
          <p className={styles.formHint}>{t("authScan.excludedHelp")}</p>

          <label className={styles.authorization}>
            <input
              type="checkbox"
              checked={consent}
              onChange={(event) => setConsent(event.target.checked)}
              disabled={locked}
              required={!locked}
            />
            <span>{t("authScan.consent")}</span>
          </label>

          <div className={styles.rowActions}>
            <button
              className="btn btn-primary"
              type="submit"
              disabled={locked || saving || !consent}
            >
              {saving ? t("saving") : t("authScan.save")}
            </button>
            {selected?.authenticated_scanning.configured ? (
              <button
                className="btn btn-secondary"
                type="button"
                disabled={removing}
                onClick={() => void onRemove()}
              >
                {removing ? t("saving") : t("authScan.remove")}
              </button>
            ) : null}
          </div>
        </form>
      ) : null}

      {message ? (
        <p className={styles.formHint} role="status">
          {message}
        </p>
      ) : null}
      {error ? (
        <p className={styles.error} role="alert">
          [ {error} ]
        </p>
      ) : null}
    </section>
  );
}
