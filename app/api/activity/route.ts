import { NextResponse } from 'next/server';
import { getActivityFeed } from '@/app/lib/db';

const DEFAULT_USER_ID = 'default_user';

/**
 * GET /api/activity
 * Get user activity feed
 */
export async function GET() {
  try {
    const activities = getActivityFeed(DEFAULT_USER_ID, 50);

    return NextResponse.json({
      activities
    });

  } catch (error) {
    console.error('Error fetching activity feed:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
