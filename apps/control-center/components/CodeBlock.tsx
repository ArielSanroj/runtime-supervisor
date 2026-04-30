"use client";

import { useState } from "react";

/**
 * Copy-paste code block. Used for credentials/SDK examples in onboarding
 * and for the per-finding LLM prompts in the scan dashboard. Stays
 * intentionally style-light so it inherits the surrounding theme.
 */
export function CodeBlock({ code, label = "copy" }: { code: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div style={{ position: "relative" }}>
      <button
        type="button"
        onClick={onCopy}
        className="button-secondary"
        style={{ position: "absolute", top: 8, right: 8, fontSize: 11, padding: "3px 8px" }}
      >
        {copied ? "✓ copied" : label}
      </button>
      <pre
        style={{
          background: "rgba(0,0,0,0.5)",
          border: "1px solid rgba(52,211,153,0.18)",
          borderRadius: 12,
          padding: 18,
          fontSize: 12.5,
          lineHeight: 1.55,
          overflow: "auto",
          margin: 0,
          whiteSpace: "pre-wrap",
        }}
      >
        <code>{code}</code>
      </pre>
    </div>
  );
}
