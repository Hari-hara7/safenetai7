import Link from "next/link";
import {
  ArrowRight,
  BookOpen,
  CheckCircle2,
  Puzzle,
  Globe,
  ShieldCheck,
  Sparkles,
  Zap,
} from "lucide-react";
import { type ReactNode } from "react";

import { auth } from "~/auth";
import { Button } from "~/components/ui/button";
import { Card } from "~/components/ui/card";

export default async function Home() {
  const session = await auth();

  return (
    <main className="relative min-h-screen overflow-hidden">
      <div className="absolute inset-0 opacity-[0.07] [background-image:linear-gradient(rgba(148,163,184,0.14)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.14)_1px,transparent_1px)] [background-size:48px_48px]" />

      <div className="relative mx-auto flex w-full max-w-7xl flex-col px-4 py-10 md:px-8 md:py-14">
        <header className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="grid size-10 place-items-center rounded-2xl border border-border bg-muted shadow-inner">
              <ShieldCheck className="size-5 text-primary" />
            </div>
            <div>
              <p className="font-heading text-base font-semibold tracking-tight">SafeNet AI</p>
              <p className="text-xs text-muted-foreground">Scam detection + community intelligence</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Link href="/extension">
              <Button variant="outline" className="gap-2">
                <Puzzle className="size-4" /> Extension
              </Button>
            </Link>
            {session?.user?.id ? (
              <Link href="/dashboard">
                <Button className="gap-2">
                  Open dashboard <ArrowRight className="size-4" />
                </Button>
              </Link>
            ) : (
              <>
                <Link href="/auth/login">
                  <Button variant="outline">Sign in</Button>
                </Link>
                <Link href="/auth/signup">
                  <Button className="gap-2">
                    Create account <ArrowRight className="size-4" />
                  </Button>
                </Link>
              </>
            )}
          </div>
        </header>

        <section className="mt-10 grid gap-6 lg:grid-cols-12 lg:items-stretch">
          <Card className="glass-panel relative overflow-hidden lg:col-span-7">
            <div className="pointer-events-none absolute -right-24 -top-24 size-72 rounded-full bg-primary/15 blur-3xl" />
            <div className="pointer-events-none absolute -bottom-24 -left-24 size-72 rounded-full bg-secondary/15 blur-3xl" />

            <div className="relative p-6 md:p-10">
              <div className="inline-flex items-center gap-2 rounded-full border border-border bg-muted px-3 py-1 text-xs font-semibold tracking-wide text-muted-foreground">
                <Sparkles className="size-3.5 text-primary" />
                Built for real-world scam defense
              </div>

              <h1 className="mt-5 font-heading text-4xl font-semibold tracking-tight md:text-6xl">
                Detect scams before they spread.
              </h1>
              <p className="mt-4 max-w-2xl text-base leading-relaxed text-muted-foreground md:text-lg">
                SafeNet AI helps users and teams assess suspicious links, emails, and documents, then turns reports into
                actionable community intelligence.
              </p>

              <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center">
                {session?.user?.id ? (
                  <Link href="/dashboard">
                    <Button className="h-10 gap-2 px-5">
                      Go to dashboard <ArrowRight className="size-4" />
                    </Button>
                  </Link>
                ) : (
                  <>
                    <Link href="/auth/signup">
                      <Button className="h-10 gap-2 px-5">
                        Start free <ArrowRight className="size-4" />
                      </Button>
                    </Link>
                    <Link href="/auth/login">
                      <Button variant="outline" className="h-10 px-5">
                        Sign in
                      </Button>
                    </Link>
                  </>
                )}
              </div>

              <div className="mt-8 grid gap-3 sm:grid-cols-3">
                <MiniStat label="Avg. triage" value="Seconds" />
                <MiniStat label="Outputs" value="Risk + reason" />
                <MiniStat label="Signal" value="Community feed" />
              </div>
            </div>
          </Card>

          <div className="grid gap-6 lg:col-span-5">
            <Card className="glass-panel p-6 md:p-8">
              <p className="text-xs font-semibold uppercase tracking-[0.22em] text-muted-foreground">
                What you get
              </p>
              <div className="mt-4 space-y-4">
                <FeatureRow
                  icon={<Zap className="size-4 text-primary" />}
                  title="Fast risk scoring"
                  description="Clear status labels, reason strings, and safe defaults."
                />
                <FeatureRow
                  icon={<Globe className="size-4 text-secondary" />}
                  title="Shared intelligence"
                  description="Reports power a community feed and admin workflows."
                />
                <FeatureRow
                  icon={<BookOpen className="size-4 text-accent" />}
                  title="Education built-in"
                  description="Short guidance that helps users avoid repeat attacks."
                />
              </div>
            </Card>

            <Card className="glass-panel p-6 md:p-8">
              <p className="text-xs font-semibold uppercase tracking-[0.22em] text-muted-foreground">
                Recommended workflow
              </p>
              <ol className="mt-4 space-y-3 text-sm text-muted-foreground">
                <Step text="Scan links/emails/documents before interacting." />
                <Step text="Report suspicious patterns with evidence." />
                <Step text="Admins review and respond from one console." />
              </ol>
            </Card>
          </div>
        </section>

        <section className="mt-10 grid gap-6 md:grid-cols-3">
          <ValueCard
            title="Protection that scales"
            description="Designed for individual users today and teams tomorrow."
          />
          <ValueCard
            title="Explainable outputs"
            description="Not just a score—provide the “why” to reduce risk."
          />
          <ValueCard
            title="Evidence-first reporting"
            description="Attach proof and preserve context for moderation."
          />
        </section>

        <footer className="mt-12 border-t border-border/70 py-8 text-sm text-muted-foreground">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <p>SafeNet AI — built to reduce scam impact.</p>
            <p className="text-xs">Tip: Pair the dashboard with the Chrome extension for faster reporting.</p>
          </div>
        </footer>
      </div>
    </main>
  );
}

function FeatureRow({
  icon,
  title,
  description,
}: {
  icon: ReactNode;
  title: string;
  description: string;
}) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-border bg-muted/60 p-3">
      <div className="mt-0.5 grid size-8 shrink-0 place-items-center rounded-lg border border-border bg-background">
        {icon}
      </div>
      <div>
        <p className="text-sm font-semibold text-foreground">{title}</p>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-border bg-muted/60 p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.22em] text-muted-foreground">{label}</p>
      <p className="mt-1 text-xl font-semibold tracking-tight text-foreground">{value}</p>
    </div>
  );
}

function Step({ text }: { text: string }) {
  return (
    <li className="flex items-start gap-2">
      <CheckCircle2 className="mt-0.5 size-4 text-primary" />
      <span>{text}</span>
    </li>
  );
}

function ValueCard({ title, description }: { title: string; description: string }) {
  return (
    <Card className="glass-panel p-6">
      <p className="font-heading text-lg font-semibold tracking-tight">{title}</p>
      <p className="mt-2 text-sm text-muted-foreground">{description}</p>
    </Card>
  );
}
