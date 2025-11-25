import { NextResponse } from 'next/server';
import { getDashboardStats } from '@/app/lib/db';

const DEFAULT_USER_ID = 'default_user';

/**
 * GET /api/dashboard
 * Get comprehensive dashboard statistics
 */
export async function GET() {
  try {
    const stats = getDashboardStats(DEFAULT_USER_ID);

    return NextResponse.json(stats);

  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
