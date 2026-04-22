import { NextResponse } from "next/server";
import { z } from "zod";

import { db } from "~/server/db";

const extensionReportSchema = z.object({
  platform: z.string().min(1),
  messageText: z.string().min(6),
  pageUrl: z.string().url().optional(),
  createdAt: z.string().datetime().optional(),
  proofFile: z
    .object({
      fileName: z.string().min(1),
      mimeType: z.string().min(1),
      base64Data: z.string().min(1),
      sizeBytes: z.number().int().min(1).max(8 * 1024 * 1024),
    })
    .optional(),
  analysis: z
    .object({
      isScam: z.boolean().optional(),
      riskScore: z.number().optional(),
      scamType: z.string().optional(),
      explanation: z.string().optional(),
    })
    .optional(),
});

function findFirstUrl(text: string): string | null {
  const re = /https?:\/\/[^\s]+/gi;
  const match = re.exec(text);
  return match?.[0] ?? null;
}

function buildCorsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  } as const;
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: buildCorsHeaders(),
  });
}

export async function POST(request: Request) {
  try {
    const body: unknown = await request.json();
    const parsed = extensionReportSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        {
          ok: false,
          error: "Invalid extension report payload.",
          details: parsed.error.flatten(),
        },
        {
          status: 400,
          headers: buildCorsHeaders(),
        },
      );
    }

    const input = parsed.data;
    const riskScore = Math.max(0, Math.min(100, Number(input.analysis?.riskScore ?? 0)));

    const report = await db.report.create({
      data: {
        title: `[Extension] ${input.platform.toUpperCase()} chat scam report`,
        type: "other",
        description: input.messageText,
        url: findFirstUrl(input.messageText) ?? input.pageUrl ?? null,
        reporterInfo: `Browser extension (${input.platform})`,
        status: "approved",
        moderationRaw: {
          source: "extension",
          platform: input.platform,
          analysis: input.analysis ? { ...input.analysis, riskScore } : null,
          pageUrl: input.pageUrl ?? null,
          createdAt: input.createdAt ?? null,
          hasProofFile: Boolean(input.proofFile),
        },
        approvedAt: new Date(),
        uploads: input.proofFile
          ? {
              create: {
                fileName: input.proofFile.fileName,
                mimeType: input.proofFile.mimeType,
                sizeBytes: input.proofFile.sizeBytes,
                base64Data: input.proofFile.base64Data,
              },
            }
          : undefined,
      },
      select: {
        id: true,
        status: true,
      },
    });

    return NextResponse.json(
      {
        ok: true,
        reportId: report.id,
        status: report.status,
      },
      {
        headers: buildCorsHeaders(),
      },
    );
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        error: "Failed to save extension report.",
        detail: error instanceof Error ? error.message : "unknown_error",
      },
      {
        status: 500,
        headers: buildCorsHeaders(),
      },
    );
  }
}
