"use client";

import { signIn } from "next-auth/react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "~/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "~/components/ui/card";
import { Input } from "~/components/ui/input";
import { api } from "~/trpc/react";

export default function SignupPage() {
  const router = useRouter();
  const register = api.auth.register.useMutation();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  return (
    <main className="relative flex min-h-screen items-center justify-center px-4 py-16">
      <div className="pointer-events-none absolute inset-0 opacity-[0.12] [background:radial-gradient(900px_circle_at_20%_20%,rgba(45,212,191,0.35),transparent_55%),radial-gradient(900px_circle_at_80%_10%,rgba(167,139,250,0.28),transparent_55%),radial-gradient(900px_circle_at_50%_90%,rgba(251,191,36,0.18),transparent_55%)]" />
      <Card className="glass-panel relative w-full max-w-md">
        <CardHeader>
          <CardTitle className="font-heading text-xl tracking-tight">Create account</CardTitle>
          <CardDescription>Join SafeNet AI to track scans and report scams.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-3"
            onSubmit={async (e) => {
              e.preventDefault();
              setError(null);

              try {
                await register.mutateAsync({
                  name: name || undefined,
                  email,
                  password,
                });

                const result = await signIn("credentials", {
                  email,
                  password,
                  redirect: false,
                  callbackUrl: "/dashboard",
                });

                if (result?.error) {
                  setError("Signup succeeded, but auto-login failed. Please sign in.");
                  router.push("/auth/login");
                  return;
                }

                router.push("/dashboard");
                router.refresh();
              } catch (mutationError) {
                const message =
                  mutationError instanceof Error
                    ? mutationError.message
                    : "Unable to create account.";
                setError(message);
              }
            }}
          >
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Name (optional)" />
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
              placeholder="Minimum 6 characters"
              minLength={6}
              required
            />
            {error && <p className="text-sm text-destructive">{error}</p>}
            <Button
              className="w-full"
              disabled={register.isPending}
            >
              {register.isPending ? "Creating account..." : "Create account"}
            </Button>
            <p className="text-sm text-muted-foreground">
              Already have an account?{" "}
              <Link href="/auth/login" className="text-primary hover:underline">
                Sign in
              </Link>
            </p>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}
