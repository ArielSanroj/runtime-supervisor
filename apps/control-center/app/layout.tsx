Page_DownPage_DownPage_DownPage_DownPage_DownPage_DownPage_DownPage_DownPage_DownPage_Downimport type { Metadata } from "next";
import { Space_Grotesk, DM_Sans } from "next/font/google";
import "./globals.css";
import Script from "next/script";

const spaceGrotesk = Space_Grotesk({
    variable: "--font-heading",
    subsets: ["latin"],
    weight: ["500", "600", "700"],
    display: "swap",
});

const dmSans = DM_Sans({
    variable: "--font-sans-body",
    subsets: ["latin"],
    weight: ["400", "500", "600"],
    display: "swap",
});

export const metadata: Metadata = {
    metadataBase: new URL("https://www.vibefixing.me"),
    title: "AI Agent Security Scanner — Vibefixing",
    description:
          "Scan your AI agent repo and find unsafe tool calls before shipping. Detect prompt injection, unguarded Stripe charges, and DB mutations. Free scan.",
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
    alternates: {
          canonical: "https://www.vibefixing.me",
    },
    openGraph: {
          title: "AI Agent Security Scanner — Vibefixing",
          description:
                  "Scan your repo and ship AI agents with guardrails. Find unsafe tool calls before an LLM touches Stripe, your DB, or customer data.",
          url: "https://www.vibefixing.me",
          siteName: "Vibefixing",
          type: "website",
          images: [
            {
                      url: "/og-image.png",
                      width: 1200,
                      height: 630,
                      alt: "Vibefixing — AI Agent Security Scanner",
            },
                ],
    },
    twitter: {
          card: "summary_large_image",
          title: "AI Agent Security Scanner — Vibefixing",
          description:
                  "Scan your repo and ship AI agents with guardrails. Find unsafe tool calls before an LLM touches Stripe, your DB, or customer data.",
          images: ["/og-image.png"],
    },
};

const schemaOrg = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: "Vibefixing",
    applicationCategory: "DeveloperApplication",
    applicationSubCategory: "SecurityApplication",
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

const faqSchema = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: [
      {
              "@type": "Question",
              name: "What is Vibefixing and what does it scan?",
              acceptedAnswer: {
                        "@type": "Answer",
                        text: "Vibefixing is a runtime supervisor and security scanner for AI agents. It statically analyzes your codebase to find unsafe tool calls your AI agent can execute before they reach production: unguarded Stripe charges, raw database mutations, filesystem writes, and shell commands.",
              },
      },
      {
              "@type": "Question",
              name: "How does Vibefixing prevent prompt injection in AI agents?",
              acceptedAnswer: {
                        "@type": "Answer",
                        text: "Vibefixing identifies tool calls that lack input validation or guardrails, which are the primary attack surface for prompt injection. By flagging every path where an LLM output can trigger an irreversible action without a human confirmation step, it eliminates the conditions that make injection exploits dangerous.",
              },
      },
      {
              "@type": "Question",
              name: "Is Vibefixing safe to use for vibe coders shipping with AI-generated code?",
              acceptedAnswer: {
                        "@type": "Answer",
                        text: "Yes. Vibefixing is designed for vibe coders: developers shipping fast with AI assistants like Claude, Cursor, or Copilot. It catches risky patterns LLMs commonly generate: unguarded API calls, database deletes without confirmation, and credential exposure in tool call arguments.",
              },
      },
      {
              "@type": "Question",
              name: "Does Vibefixing work with any AI agent framework?",
              acceptedAnswer: {
                        "@type": "Answer",
                        text: "Vibefixing analyzes your repository at the code level, so it works with any agent framework: LangChain, LlamaIndex, CrewAI, custom OpenAI function-calling, Anthropic tool use, or plain Python scripts. No instrumentation or runtime hooks required.",
              },
      },
      {
              "@type": "Question",
              name: "What unsafe actions does Vibefixing detect?",
              acceptedAnswer: {
                        "@type": "Answer",
                        text: "Vibefixing detects: unguarded payment calls (Stripe, PayPal), raw SQL mutations (INSERT, UPDATE, DELETE without transactions), filesystem writes and deletes, subprocess and shell execution, email sends without confirmation, and external HTTP calls that can exfiltrate data. Each finding includes the file, line, and a fix.",
              },
      },
      {
              "@type": "Question",
              name: "How long does a Vibefixing scan take?",
              acceptedAnswer: {
                        "@type": "Answer",
                        text: "A public repository scan typically completes in under 60 seconds. Vibefixing uses static analysis and does not run your code or require an API key for the scan. Results include a risk score, a list of unsafe actions, and copy-paste guardrail code for each finding.",
              },
      },
      {
              "@type": "Question",
              name: "Does Vibefixing scan every pull request automatically?",
              acceptedAnswer: {
                        "@type": "Answer",
                        text: "Yes. Install the Vibefixing GitHub App on your repo and every pull request gets scanned automatically. Within 5 seconds of opening a PR, vibefixing diffs the head ref against your previous scan and posts a comment listing only the new unsafe call-sites. Clean PRs get nothing — no spam. Free for public repos; private repos and CI integration are part of Builder ($29/mo), while team workflows, SSO, and org-level controls start at Pro ($99/workspace/mo).",
              },
      },
      {
              "@type": "Question",
              name: "How is Vibefixing different from regular code review or static analysis?",
              acceptedAnswer: {
                        "@type": "Answer",
                        text: "Code review and SAST tools catch bugs in code your tests already cover. Vibefixing catches what your tests cannot: actions an LLM can fire at runtime in ways no test case anticipated. Refunds the model decides to issue, files it decides to delete, emails it decides to send. Each detector maps to a runtime guard you can drop in with one line.",
              },
      },
      {
              "@type": "Question",
              name: "How is Vibefixing different from Snyk or Semgrep for AI agents?",
              acceptedAnswer: {
                        "@type": "Answer",
                        text: "Snyk and Semgrep are built for human-written code vulnerabilities: CVEs, dependency audits, known patterns. Vibefixing is built specifically for LLM-driven execution paths — the tool calls an AI agent fires at runtime based on user input. It understands agent shapes (tool-using, chatbot, RAG, MCP-server) and surfaces risk framed around what the model can do, not what a human wrote incorrectly.",
              },
      },
      {
              "@type": "Question",
              name: "Does Vibefixing replace runtime monitoring tools like LangSmith?",
              acceptedAnswer: {
                        "@type": "Answer",
                        text: "No — they are complementary. LangSmith and similar tools observe what your agent does at runtime after deployment. Vibefixing runs before deployment, on your static codebase, to catch unsafe tool call patterns before they ever reach production. Use Vibefixing in CI to prevent risky code from shipping, and runtime monitoring to observe behavior after it ships.",
              },
      },
        ],
};

export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
          <html lang="en" className={`${spaceGrotesk.variable} ${dmSans.variable}`}>
                  <body>
                    {/* Google Tag Manager - noscript fallback */}
                          <noscript>
                                    <iframe
                                                  src="https://www.googletagmanager.com/ns.html?id=GTM-TVK2KK79"
                                                  height="0"
                                                  width="0"
                                                  style={{ display: "none", visibility: "hidden" }}
                                                />
                          </noscript>
                  
                    {/* Google Tag Manager - script */}
                          <Script
                                      id="gtm-script"
                                      strategy="afterInteractive"
                                      dangerouslySetInnerHTML={{
                                                    __html: `(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src='https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);})(window,document,'script','dataLayer','GTM-TVK2KK79');`,
                                      }}
                                    />
                  
                    {/* Hotjar - replace HOTJAR_SITE_ID with your actual site ID from hotjar.com */}
                          <Script
                                      id="hotjar-script"
                                      strategy="afterInteractive"
                                      dangerouslySetInnerHTML={{
                                                    __html: `(function(h,o,t,j,a,r){h.hj=h.hj||function(){(h.hj.q=h.hj.q||[]).push(arguments)};h._hjSettings={hjid:HOTJAR_SITE_ID,hjsv:6};a=o.getElementsByTagName('head')[0];r=o.createElement('script');r.async=1;r.src=t+h._hjSettings.hjid+j+h._hjSettings.hjsv;a.appendChild(r);})(window,document,'https://static.hotjar.com/c/hotjar-','.js?sv=');`,
                                      }}
                                    />
                  
                          <script
                                      type="application/ld+json"
                                      dangerouslySetInnerHTML={{ __html: JSON.stringify(schemaOrg) }}
                                    />
                          <script
                                      type="application/ld+json"
                                      dangerouslySetInnerHTML={{ __html: JSON.stringify(faqSchema) }}
                                    />
                    {children}
                  </body>
          </html>
        );
}
