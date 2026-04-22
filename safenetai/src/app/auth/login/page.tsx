"use client";

import { signIn } from "next-auth/react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { Button } from "~/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "~/components/ui/card";
import { Input } from "~/components/ui/input";

export default function LoginPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get("callbackUrl") ?? "/dashboard";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  return (
    <main className="relative flex min-h-screen items-center justify-center px-4 py-16">
      <div className="pointer-events-none absolute inset-0 opacity-[0.12] [background:radial-gradient(900px_circle_at_20%_20%,rgba(45,212,191,0.35),transparent_55%),radial-gradient(900px_circle_at_80%_10%,rgba(167,139,250,0.28),transparent_55%),radial-gradient(900px_circle_at_50%_90%,rgba(251,191,36,0.18),transparent_55%)]" />
      <Card className="glass-panel relative w-full max-w-md">
        <CardHeader>
          <CardTitle className="font-heading text-xl tracking-tight">Sign in</CardTitle>
          <CardDescription>Access your dashboard, scans, and community reports.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-3"
            onSubmit={async (e) => {
              e.preventDefault();
              setIsLoading(true);
              setError(null);

              const result = await signIn("credentials", {
                email,
                password,
                redirect: false,
                callbackUrl,
              });

              setIsLoading(false);

              if (result?.error) {
                setError("Invalid email or password.");
                return;
              }

              router.push(callbackUrl);
              router.refresh();
            }}
          >
            <Input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              required
            />
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              required
            />
            {error && <p className="text-sm text-destructive">{error}</p>}
            <Button className="w-full" disabled={isLoading}>
              {isLoading ? "Signing in..." : "Sign in"}
            </Button>
            <p className="text-sm text-muted-foreground">
              New here?{" "}
              <Link href="/auth/signup" className="text-primary hover:underline">
                Create an account
              </Link>
            </p>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}
