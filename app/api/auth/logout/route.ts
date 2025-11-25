import { NextRequest, NextResponse } from 'next/server';
import { clearSessionCookie } from '@/app/lib/auth';
import { cookies } from 'next/headers';

/**
 * POST /api/auth/logout
 * Logout current user
 */
export async function POST(request: NextRequest) {
  try {
    const cookieStore = await cookies();
    const sessionId = cookieStore.get('tekton_session')?.value;

    // Note: We could delete the session from the store here
    // but cookies will expire anyway

    const response = NextResponse.json({
      success: true,
      message: 'Logged out successfully'
    });

    clearSessionCookie(response);

    return response;

  } catch (error) {
    console.error('Error logging out:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
