import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
    title: "Vibefixing — AI Agent Security Scanner | Guardrails for Vibe Coders",
    description:
          "Vibefixing scans your repo and finds unsafe AI agent actions before they hit production. Detect prompt injection risks, unguarded Stripe calls, DB mutations, and filesystem writes. Free public scan.",
    keywords: [
          "ai agent guardrails",
          "vibe coding security",
          "llm tool call security",
          "prevent prompt injection",
          "agent runtime security scanner",
          "ai agent security",
          "runtime supervisor",
        ],
    openGraph: {
          title: "Vibefixing — AI Agent Security Scanner",
          description:
                  "Scan your repo and ship AI agents with guardrails. Find unsafe tool calls before an LLM touches Stripe, your DB, or customer data.",
          url: "https://www.vibefixing.me",
          siteName: "Vibefixing",
          type: "website",
    },
    twitter: {
          card: "summary_large_image",
          title: "Vibefixing — AI Agent Security Scanner",
          description:
                  "Scan your repo and ship AI agents with guardrails. Find unsafe tool calls before an LLM touches Stripe, your DB, or customer data.",
    },
};

const schemaOrg = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: "Vibefixing",
    applicationCategory: "DeveloperApplication",
    operatingSystem: "Web",
    url: "https://www.vibefixing.me",
    description:
          "AI agent security scanner. Scan your repository to find unsafe tool calls — money movement, DB mutations, filesystem writes, LLM prompt injection — before shipping to production.",
    offers: {
          "@type": "Offer",
          price: "0",
          priceCurrency: "USD",
    },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
    return (
          <html lang="en">
                <head>
                        <script
                                    type="application/ld+json"
                                    dangerouslySetInnerHTML={{ __html: JSON.stringify(schemaOrg) }}
                                  />
                </head>head>
                <body>{children}</body>body>
          </html>html>
        );
}</html>
