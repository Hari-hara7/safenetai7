import { NextResponse, type NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";

import { env } from "~/env";

const protectedRoutes = ["/dashboard"];

export default async function middleware(req: NextRequest) {
  const pathname = req.nextUrl.pathname;
  const isProtected = protectedRoutes.some((route) =>
    pathname.startsWith(route),
  );

  if (!isProtected) {
    return NextResponse.next();
  }

  const token = await getToken({ req, secret: env.AUTH_SECRET });

  if (!token) {
    const loginUrl = new URL("/auth/login", req.url);
    loginUrl.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*"],
};
