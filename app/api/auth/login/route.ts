import { NextRequest, NextResponse } from 'next/server';
import { getUserByEmail } from '@/app/lib/db';
import { createSession, setSessionCookie } from '@/app/lib/auth';
import crypto from 'crypto';

/**
 * POST /api/auth/login
 * Login user with email and password
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email, password } = body;

    // Validation
    if (!email || !password) {
      return NextResponse.json(
        { error: 'Email and password are required' },
        { status: 400 }
      );
    }

    // Find user
    const user = getUserByEmail(email) as any;

    if (!user) {
      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      );
    }

    // Verify password
    const passwordHash = crypto.createHash('sha256').update(password).digest('hex');

    if (passwordHash !== user.password_hash) {
      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      );
    }

    // Create session
    const sessionId = createSession(user.user_id);

    // Create response with session cookie
    const response = NextResponse.json({
      success: true,
      message: 'Logged in successfully',
      user: {
        userId: user.user_id,
        username: user.username,
        email: user.email,
        level: user.level,
        tokens: user.tokens
      }
    });

    // Pass userId for persistent cookie (survives hot reload)
    setSessionCookie(response, sessionId, user.user_id);

    return response;

  } catch (error) {
    console.error('Error logging in:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
