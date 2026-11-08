import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "AI-Powered Threat & Digital Trust Intelligence",
  description: "Web threat correlation and digital trust intelligence platform",
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