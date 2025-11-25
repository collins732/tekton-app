import { NextRequest, NextResponse } from 'next/server';
import { getNotifications, markNotificationAsRead, markAllNotificationsAsRead, getUnreadNotificationCount } from '@/app/lib/db';

const DEFAULT_USER_ID = 'default_user';

/**
 * GET /api/notifications
 * Get user notifications
 */
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const unreadOnly = searchParams.get('unread') === 'true';

    const notifications = getNotifications(DEFAULT_USER_ID, unreadOnly);
    const unreadCount = getUnreadNotificationCount(DEFAULT_USER_ID);

    return NextResponse.json({
      notifications,
      unread_count: unreadCount
    });

  } catch (error) {
    console.error('Error fetching notifications:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * PATCH /api/notifications
 * Mark notification(s) as read
 */
export async function PATCH(request: NextRequest) {
  try {
    const body = await request.json();
    const { notification_id, mark_all } = body;

    if (mark_all) {
      markAllNotificationsAsRead(DEFAULT_USER_ID);
      return NextResponse.json({
        success: true,
        message: 'All notifications marked as read'
      });
    }

    if (!notification_id) {
      return NextResponse.json(
        { error: 'notification_id is required' },
        { status: 400 }
      );
    }

    markNotificationAsRead(notification_id);

    return NextResponse.json({
      success: true,
      message: 'Notification marked as read'
    });

  } catch (error) {
    console.error('Error updating notification:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
