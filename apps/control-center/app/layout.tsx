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
  verification: {
    google: "8oQicBLD59p5ixSUL7OsFDrM43qecrpBJLlU9TqSydk",
  },
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
      <body>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(schemaOrg) }}
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: '{"@context":"https://schema.org","@type":"FAQPage","mainEntity":[{"@type":"Question","name":"What is Vibefixing?","acceptedAnswer":{"@type":"Answer","text":"Vibefixing is a runtime supervisor and security scanner for AI agents. It finds unsafe tool calls before they reach production."}},{"@type":"Question","name":"How does Vibefixing prevent prompt injection?","acceptedAnswer":{"@type":"Answer","text":"By flagging every path where an LLM output can trigger an irreversible action without a confirmation step."}},{"@type":"Question","name":"Does Vibefixing work with any AI agent framework?","acceptedAnswer":{"@type":"Answer","text":"Yes: LangChain, LlamaIndex, CrewAI, OpenAI function-calling, Anthropic tool use, or plain Python scripts."}},{"@type":"Question","name":"What unsafe actions does Vibefixing detect?","acceptedAnswer":{"@type":"Answer","text":"Unguarded payment calls, raw SQL mutations, filesystem writes, subprocess execution, and HTTP calls that can exfiltrate data."}},{"@type":"Question","name":"How long does a scan take?","acceptedAnswer":{"@type":"Answer","text":"Under 60 seconds using static analysis, no code execution required."}}]}' }}
        />
        {children}
      </body>
    </html>
  );
}
