import { NextResponse } from 'next/server';
import { getUserFromSession } from '@/app/lib/auth';
import { getUser } from '@/app/lib/db';

/**
 * GET /api/auth/session
 * Get current user session
 */
export async function GET() {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json(
        { authenticated: false },
        { status: 401 }
      );
    }

    const user = getUser(userId) as any;

    if (!user) {
      return NextResponse.json(
        { authenticated: false },
        { status: 401 }
      );
    }

    return NextResponse.json({
      authenticated: true,
      user: {
        userId: user.user_id,
        username: user.username,
        email: user.email,
        level: user.level,
        tokens: user.tokens,
        plan: user.plan,
        avatar: user.avatar
      }
    });

  } catch (error) {
    console.error('Error getting session:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
