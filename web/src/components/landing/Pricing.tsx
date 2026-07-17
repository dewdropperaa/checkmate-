"use client";

import { useMemo, useState } from "react";
import { useLocale, useTranslations } from "next-intl";
import { Link } from "@/i18n/navigation";
import {
  FEATURE_CATALOG,
  PLANS,
  type BillingInterval,
  formatPlanPrice,
} from "@/config/plans";
import styles from "./landing.module.css";

export function Pricing() {
  const t = useTranslations("plans");
  const tFeatures = useTranslations("featureKeys");
  const locale = useLocale();
  const [interval, setInterval] = useState<BillingInterval>("monthly");

  const plans = useMemo(() => PLANS, []);

  return (
    <section id="pricing" className="section" aria-labelledby="pricing-heading">
      <div className="container">
        <p className="section-label">plans</p>
        <h2 id="pricing-heading" className="section-title">
          {t("title")}
        </h2>
        <p className="section-sub">{t("subtitle")}</p>

        <div className={styles.billingToggle} role="group" aria-label="Billing interval">
          <button
            type="button"
            aria-pressed={interval === "monthly"}
            onClick={() => setInterval("monthly")}
          >
            {t("monthly")}
          </button>
          <button
            type="button"
            aria-pressed={interval === "yearly"}
            onClick={() => setInterval("yearly")}
          >
            {t("yearly")}
          </button>
        </div>

        <div className={styles.pricingGrid}>
          {plans.map((plan) => {
            const price = formatPlanPrice(plan.prices[interval], locale, interval);
            const name = t(`${plan.id}.name`);
            const cardClass = plan.highlighted
              ? `${styles.priceCard} ${styles.priceCardHighlight}`
              : styles.priceCard;

            return (
              <article key={plan.id} className={cardClass}>
                <h3 className={styles.priceName}>{name}</h3>
                <p className={styles.priceAmount}>{price}</p>
                <p className={styles.priceBlurb}>{t(`${plan.id}.blurb`)}</p>
                <ul className={styles.priceMeta}>
                  <li>
                    {plan.maxTargets == null
                      ? t("targetsCustom")
                      : plan.maxTargets === 1
                        ? t("targets", { count: plan.maxTargets })
                        : t("targets_plural", { count: plan.maxTargets })}
                  </li>
                  <li>
                    {plan.scansPerMonth == null
                      ? t("scansCustom")
                      : t("scans", { count: plan.scansPerMonth })}
                  </li>
                </ul>
                <ul className={styles.featureList}>
                  {plan.features.map((key) => (
                    <li
                      key={key}
                      data-todo={FEATURE_CATALOG[key].todo ? "true" : undefined}
                    >
                      {tFeatures(key)}
                    </li>
                  ))}
                </ul>
                {plan.cta === "contact" ? (
                  /* TODO: confirm public sales/contact address before launch */
                  <a href="mailto:hello@checkmate.ma" className="btn btn-secondary btn-block">
                    {t("ctaContact")}
                  </a>
                ) : (
                  <Link
                    href="/signup"
                    className={`btn ${plan.highlighted ? "btn-primary" : "btn-secondary"} btn-block`}
                  >
                    {t("ctaSignup", { plan: name })}
                  </Link>
                )}
              </article>
            );
          })}
        </div>
      </div>
    </section>
  );
}
