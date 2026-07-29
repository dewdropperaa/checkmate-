import type { MetadataRoute } from "next";

/**
 * Discourage public web archives (Wayback Machine, etc.).
 * Complement with `noarchive` in page metadata and X-Robots-Tag headers.
 */
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
      },
      {
        userAgent: "ia_archiver",
        disallow: "/",
      },
      {
        userAgent: "archive.org_bot",
        disallow: "/",
      },
      {
        userAgent: "Wayback",
        disallow: "/",
      },
    ],
  };
}
