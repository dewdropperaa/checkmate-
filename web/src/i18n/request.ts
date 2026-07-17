import { getRequestConfig } from "next-intl/server";
import en from "../../messages/en.json";
import fr from "../../messages/fr.json";
import { routing } from "./routing";

const messages = { en, fr } as const;

export default getRequestConfig(async ({ requestLocale }) => {
  let locale = await requestLocale;
  if (!locale || !routing.locales.includes(locale as "fr" | "en")) {
    locale = routing.defaultLocale;
  }

  return {
    locale,
    messages: messages[locale as keyof typeof messages],
  };
});
