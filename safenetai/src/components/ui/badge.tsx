import * as React from "react";

import { cn } from "~/lib/utils";

function Badge({ className, ...props }: React.ComponentProps<"span">) {
  return (
    <span
      data-slot="badge"
      className={cn(
        "inline-flex items-center rounded-full border border-border bg-muted px-2.5 py-1 text-xs font-semibold tracking-wide text-foreground",
        className,
      )}
      {...props}
    />
  );
}

export { Badge };
