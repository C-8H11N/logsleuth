import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "LogSleuth | Web Log Investigation",
  description: "Local-first web log investigation workspace for defensive security teams.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
