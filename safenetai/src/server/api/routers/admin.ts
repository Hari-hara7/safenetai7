import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { env } from "~/env";
import { isAdminUser } from "~/server/authz";
import { createTRPCRouter, protectedProcedure } from "~/server/api/trpc";

function assertAdmin(email?: string | null) {
  if (!isAdminUser(email)) {
    throw new TRPCError({ code: "FORBIDDEN", message: "Admin access required." });
  }
}

export const adminRouter = createTRPCRouter({
  overview: protectedProcedure.query(async ({ ctx }) => {
    assertAdmin(ctx.session.user.email);

    const [
      totalScans,
      dangerousScans,
      suspiciousScans,
      safeScans,
      totalReports,
      approvedReports,
      rejectedReports,
      reportsByType,
      scansByType,
      latestReports,
    ] = await Promise.all([
      ctx.db.scan.count(),
      ctx.db.scan.count({ where: { status: "dangerous" } }),
      ctx.db.scan.count({ where: { status: "suspicious" } }),
      ctx.db.scan.count({ where: { status: "safe" } }),
      ctx.db.report.count(),
      ctx.db.report.count({ where: { status: "approved" } }),
      ctx.db.report.count({ where: { status: "rejected" } }),
      ctx.db.report.groupBy({ by: ["type"], _count: { _all: true } }),
      ctx.db.scan.groupBy({ by: ["type"], _count: { _all: true } }),
      ctx.db.report.findMany({
        orderBy: { createdAt: "desc" },
        take: 20,
        include: {
          user: { select: { id: true, name: true, email: true } },
        },
      }),
    ]);

    return {
      totalScans,
      dangerousScans,
      suspiciousScans,
      safeScans,
      totalReports,
      approvedReports,
      rejectedReports,
      reportsByType,
      scansByType,
      latestReports,
    };
  }),

  reviewReports: protectedProcedure
    .input(
      z.object({
        status: z.enum(["pending", "approved", "rejected"]).optional(),
        limit: z.number().int().min(1).max(200).default(100),
      }),
    )
    .query(async ({ ctx, input }) => {
      assertAdmin(ctx.session.user.email);

      return ctx.db.report.findMany({
        where: input.status ? { status: input.status } : undefined,
        orderBy: { createdAt: "desc" },
        take: input.limit,
        include: {
          uploads: {
            select: {
              id: true,
              fileName: true,
              mimeType: true,
              sizeBytes: true,
              base64Data: true,
              createdAt: true,
            },
          },
          user: {
            select: {
              id: true,
              name: true,
              email: true,
            },
          },
        },
      });
    }),

  updateReportStatus: protectedProcedure
    .input(
      z.object({
        reportId: z.string().min(1),
        status: z.enum(["approved", "rejected"]),
        reason: z.string().min(4).max(500),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      assertAdmin(ctx.session.user.email);

      return ctx.db.report.update({
        where: { id: input.reportId },
        data: {
          status: input.status,
          moderationVerdict: input.status === "approved" ? "APPROVED" : "REJECTED",
          moderationReason: `[Admin Override] ${input.reason}`,
          approvedAt: input.status === "approved" ? new Date() : null,
        },
      });
    }),

  supportReply: protectedProcedure
    .input(
      z.object({
        userMessage: z.string().min(4).max(2000),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      assertAdmin(ctx.session.user.email);

      const prompt = [
        "You are SafeNet AI admin support assistant.",
        "Answer users about scam safety, reporting, and account safety in concise and practical steps.",
        "Keep answer under 120 words.",
        `User question: ${input.userMessage}`,
      ].join("\n");

      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${env.GEMINI_API_KEY}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
          }),
        },
      );

      const payload: unknown = await response.json();

      const geminiSchema = z.object({
        candidates: z
          .array(
            z.object({
              content: z
                .object({
                  parts: z.array(z.object({ text: z.string().optional() })).optional(),
                })
                .optional(),
            }),
          )
          .optional(),
      });

      const parsed = geminiSchema.safeParse(payload);
      const replyText =
        parsed.success
          ? (parsed.data.candidates?.[0]?.content?.parts ?? [])
              .map((part) => part.text ?? "")
              .join("\n")
              .trim()
          : "";
      const reply = replyText.length > 0 ? replyText : "Support is currently busy. Please retry in a moment.";

      return { reply };
    }),
});
