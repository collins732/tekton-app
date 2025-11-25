import { NextRequest, NextResponse } from 'next/server';
import { getUser, updateUser } from '@/app/lib/db';
import { getUserFromSession } from '@/app/lib/auth';
import crypto from 'crypto';

/**
 * GET /api/security
 * Get security settings
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

    const user = getUser(userId) as any;

    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      );
    }

    return NextResponse.json({
      two_factor_enabled: !!user.two_factor_enabled,
      active_sessions: [
        {
          device: 'Chrome on Windows',
          location: 'Paris, France',
          last_active: 'Just now',
          current: true
        },
        {
          device: 'Firefox on MacOS',
          location: 'Lyon, France',
          last_active: '2 days ago',
          current: false
        }
      ]
    });

  } catch (error) {
    console.error('Error fetching security settings:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * PATCH /api/security
 * Update security settings
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
    const { action, current_password, new_password, enable_2fa } = body;

    const user = getUser(userId) as any;

    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      );
    }

    // Change password
    if (action === 'change_password') {
      if (!current_password || !new_password) {
        return NextResponse.json(
          { error: 'current_password and new_password are required' },
          { status: 400 }
        );
      }

      // Verify current password
      const currentHash = crypto.createHash('sha256').update(current_password).digest('hex');
      if (currentHash !== user.password_hash) {
        return NextResponse.json(
          { error: 'Current password is incorrect' },
          { status: 401 }
        );
      }

      // Validate new password
      if (new_password.length < 8) {
        return NextResponse.json(
          { error: 'New password must be at least 8 characters' },
          { status: 400 }
        );
      }

      // Update password
      const newHash = crypto.createHash('sha256').update(new_password).digest('hex');
      updateUser(userId, { password_hash: newHash });

      return NextResponse.json({
        success: true,
        message: 'Password changed successfully'
      });
    }

    // Toggle 2FA
    if (action === 'toggle_2fa') {
      if (enable_2fa === undefined) {
        return NextResponse.json(
          { error: 'enable_2fa field is required' },
          { status: 400 }
        );
      }

      updateUser(userId, { two_factor_enabled: enable_2fa ? 1 : 0 });

      return NextResponse.json({
        success: true,
        message: enable_2fa ? '2FA enabled successfully' : '2FA disabled successfully',
        two_factor_enabled: !!enable_2fa,
        secret: enable_2fa ? 'TEKTON2FA' + Math.random().toString(36).substring(2, 10).toUpperCase() : null
      });
    }

    // Revoke session
    if (action === 'revoke_session') {
      const { session_id } = body;

      if (!session_id) {
        return NextResponse.json(
          { error: 'session_id is required' },
          { status: 400 }
        );
      }

      // In a real app, would revoke the actual session
      // For demo, just return success
      return NextResponse.json({
        success: true,
        message: 'Session revoked successfully'
      });
    }

    return NextResponse.json(
      { error: 'Invalid action. Use: change_password, toggle_2fa, or revoke_session' },
      { status: 400 }
    );

  } catch (error) {
    console.error('Error updating security settings:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
