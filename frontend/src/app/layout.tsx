import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "SpecterShield AI | Autonomous Threat Intelligence & Ledger",
  description:
    "SpecterShield AI provides intelligent web threat analysis and tamper-evident on-chain verification for security reports.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-zinc-950 text-zinc-100 antialiased min-h-screen">
        {children}
      </body>
    </html>
  );
}