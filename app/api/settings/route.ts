import { NextRequest, NextResponse } from 'next/server';
import { getNotificationSettings, updateNotificationSettings } from '@/app/lib/db';
import { getUserFromSession } from '@/app/lib/auth';

/**
 * GET /api/settings
 * Get user settings (notifications, etc.)
 */
export async function GET() {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const settings = getNotificationSettings(userId);

    return NextResponse.json({
      notifications: settings || {
        scan_complete: 1,
        vuln_found: 1,
        weekly_report: 1,
        achievement: 1,
        rank_change: 1
      }
    });

  } catch (error) {
    console.error('Error fetching settings:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * PATCH /api/settings
 * Update user settings
 */
export async function PATCH(request: NextRequest) {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const body = await request.json();
    const { notifications } = body;

    if (notifications) {
      updateNotificationSettings(userId, notifications);
    }

    const updatedSettings = getNotificationSettings(userId);

    return NextResponse.json({
      success: true,
      notifications: updatedSettings
    });

  } catch (error) {
    console.error('Error updating settings:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
