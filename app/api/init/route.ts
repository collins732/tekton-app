import { NextResponse } from 'next/server';
import { createUser, getUser, addTokens } from '@/app/lib/db';
import crypto from 'crypto';

/**
 * GET /api/init
 * Initialize default user and return user data
 */
export async function GET() {
  try {
    const DEFAULT_USER_ID = 'default_user';

    // Check if user already exists
    let user = getUser(DEFAULT_USER_ID) as any;

    if (!user) {
      // Create default user
      const passwordHash = crypto.createHash('sha256').update('password123').digest('hex');

      createUser({
        userId: DEFAULT_USER_ID,
        username: 'collins_dev',
        email: 'collins@tekton.io',
        passwordHash
      });

      // Add initial tokens (327 to match frontend)
      addTokens(DEFAULT_USER_ID, 277); // User starts with 50, add 277 to get 327

      user = getUser(DEFAULT_USER_ID);
    }

    return NextResponse.json({
      success: true,
      user: {
        user_id: user.user_id,
        username: user.username,
        email: user.email,
        level: user.level,
        tokens: user.tokens,
        plan: user.plan
      }
    });

  } catch (error) {
    console.error('Error initializing user:', error);
    return NextResponse.json(
      { error: 'Failed to initialize user' },
      { status: 500 }
    );
  }
}
