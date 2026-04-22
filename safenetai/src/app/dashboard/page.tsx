import { redirect } from "next/navigation";

import { auth, signOut } from "~/auth";
import { DashboardClient } from "~/components/safenet/dashboard-client";
import { Button } from "~/components/ui/button";
import { isAdminUser } from "~/server/authz";

export default async function DashboardPage() {
  const session = await auth();

  if (!session?.user?.id) {
    redirect("/auth/login");
  }

  const isAdmin = isAdminUser(session.user.email);

  return (
    <main className="min-h-screen">
      <div className="mx-auto flex w-full max-w-7xl items-center justify-between border-b border-border/70 bg-muted/40 px-4 py-5 md:px-8">
        <div className="space-y-1">
          <p className="text-xs uppercase tracking-[0.25em] text-primary">Threat Intelligence Console</p>
          <h1 className="font-heading text-2xl font-bold">SafeNet AI Command Center</h1>
          <p className="text-sm text-muted-foreground">
            Detect, educate, and respond with enterprise-grade threat defense workflows.
          </p>
        </div>
        <form
          action={async () => {
            "use server";
            await signOut({ redirectTo: "/auth/login" });
          }}
        >
          <Button type="submit" variant="outline">
            Sign out
          </Button>
        </form>
      </div>
      <DashboardClient
        userName={session.user.name ?? "SafeNet User"}
        userEmail={session.user.email ?? "Unknown"}
        isAdmin={isAdmin}
      />
    </main>
  );
}
