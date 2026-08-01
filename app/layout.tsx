import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "LogSleuth | Web 日志安全调查平台",
  description: "本地优先的 Web 日志安全调查与攻击时间线分析平台。",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="zh-CN"><body>{children}</body></html>;
}
