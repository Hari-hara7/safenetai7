import Link from "next/link";
import { Download, ShieldCheck, Puzzle } from "lucide-react";

import { Card } from "~/components/ui/card";
import { Button } from "~/components/ui/button";

export default function ExtensionDownloadPage() {
  return (
    <main className="mx-auto min-h-screen w-full max-w-5xl px-4 py-10 md:px-8">
      <section className="glass-panel rounded-3xl p-6 md:p-10">
        <div className="inline-flex items-center gap-2 rounded-full border border-border bg-muted px-3 py-1 text-xs font-semibold tracking-wide text-muted-foreground">
          <Puzzle className="size-3.5 text-primary" />
          Chrome Extension
        </div>
        <h1 className="mt-4 font-heading text-4xl font-semibold tracking-tight md:text-5xl">
          SafeNet AI Extension
        </h1>
        <p className="mt-3 max-w-3xl text-muted-foreground">
          Detect suspicious messages in WhatsApp, LinkedIn, and Gmail, then report incidents directly to your SafeNet dashboard.
        </p>
      </section>

      <section className="mt-6 grid gap-6 md:grid-cols-2">
        <Card className="glass-panel p-6">
          <h2 className="mb-3 flex items-center gap-2 text-xl font-semibold">
            <Download className="size-5 text-primary" /> Install (Load Unpacked)
          </h2>
          <ol className="space-y-2 text-sm text-muted-foreground">
            <li>1. Open `chrome://extensions` in Chrome.</li>
            <li>2. Enable <strong>Developer mode</strong>.</li>
            <li>3. Click <strong>Load unpacked</strong>.</li>
            <li>4. Select the local folder: <code>safenetai/extension-build</code>.</li>
          </ol>
          <p className="mt-3 text-xs text-muted-foreground">
            Recommended: Keep the popup configured to your deployed SafeNet URL in extension options.
          </p>
        </Card>

        <Card className="glass-panel p-6">
          <h2 className="mb-3 flex items-center gap-2 text-xl font-semibold">
            <Puzzle className="size-5 text-secondary" /> What You Get
          </h2>
          <ul className="space-y-2 text-sm text-muted-foreground">
            <li>- In-chat scam warning banners (WhatsApp, LinkedIn, Gmail)</li>
            <li>- One-click report sync to SafeNet community feed</li>
            <li>- Fast access to dashboard and report tools</li>
            <li>- UI aligned with your new Trust/Security design</li>
          </ul>
          <div className="mt-4 flex flex-wrap gap-2">
            <Link href="/dashboard">
              <Button className="gap-2"><ShieldCheck className="size-4" /> Open Dashboard</Button>
            </Link>
            <Link href="/">
              <Button variant="outline">Back Home</Button>
            </Link>
          </div>
        </Card>
      </section>
    </main>
  );
}

