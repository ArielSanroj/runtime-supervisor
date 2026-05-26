import { MetadataRoute } from "next";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        disallow: [
          "/api/",
          "/dashboard",
          "/dashboard/",
          "/repos",
          "/repos/",
          "/threats",
          "/threats/",
          "/policies",
          "/policies/",
          "/findings",
          "/findings/",
          "/review",
          "/review/",
          "/team",
          "/team/",
          "/integrations",
          "/integrations/",
          "/onboard",
          "/onboard/",
          "/scans/",
        ],
      },
      { userAgent: "GPTBot", allow: "/" },
      { userAgent: "ClaudeBot", allow: "/" },
      { userAgent: "Claude-Web", allow: "/" },
      { userAgent: "PerplexityBot", allow: "/" },
      { userAgent: "Google-Extended", allow: "/" },
      { userAgent: "CCBot", allow: "/" },
      { userAgent: "anthropic-ai", allow: "/" },
    ],
    sitemap: "https://www.vibefixing.me/sitemap.xml",
    host: "https://www.vibefixing.me",
  };
}
