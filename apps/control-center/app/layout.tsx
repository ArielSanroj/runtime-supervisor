import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Vibefixing — runtime-supervisor",
  description: "Vibefixing · runtime-supervisor — guardrails for AI agents that ship. Intercept actions, evaluate risk, block or escalate in real time.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
