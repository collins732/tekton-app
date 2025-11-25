import { NextRequest, NextResponse } from 'next/server';
import { getUser, updateUser, getUserByEmail } from '@/app/lib/db';
import { getUserFromSession } from '@/app/lib/auth';

/**
 * GET /api/account
 * Get account settings
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
      email: user.email,
      language: user.language || 'English',
      timezone: user.timezone || 'UTC+1 (Paris)',
      created_at: user.created_at
    });

  } catch (error) {
    console.error('Error fetching account:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * PATCH /api/account
 * Update account settings (email, language, timezone)
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

    // Allowed account fields
    const allowedFields = ['email', 'language', 'timezone'];
    const updates: any = {};

    allowedFields.forEach(field => {
      if (body[field] !== undefined) {
        updates[field] = body[field];
      }
    });

    if (Object.keys(updates).length === 0) {
      return NextResponse.json(
        { error: 'No valid fields to update' },
        { status: 400 }
      );
    }

    // Validate email if being updated
    if (updates.email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(updates.email)) {
        return NextResponse.json(
          { error: 'Invalid email format' },
          { status: 400 }
        );
      }

      // Check if email already exists (for other users)
      const existingUser = getUserByEmail(updates.email) as any;
      if (existingUser && existingUser.user_id !== userId) {
        return NextResponse.json(
          { error: 'Email already in use' },
          { status: 409 }
        );
      }
    }

    updateUser(userId, updates);

    const updatedUser = getUser(userId) as any;

    return NextResponse.json({
      success: true,
      message: 'Account settings updated successfully',
      user: {
        email: updatedUser.email,
        language: updatedUser.language,
        timezone: updatedUser.timezone
      }
    });

  } catch (error) {
    console.error('Error updating account:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/account
 * Delete user account
 */
export async function DELETE(request: NextRequest) {
  try {
    const body = await request.json();
    const { confirm } = body;

    if (confirm !== 'DELETE') {
      return NextResponse.json(
        { error: 'Please confirm account deletion by sending {"confirm": "DELETE"}' },
        { status: 400 }
      );
    }

    // In a real app, this would:
    // 1. Delete all user data
    // 2. Cancel subscriptions
    // 3. Send confirmation email
    // For now, we'll just return success without actually deleting

    return NextResponse.json({
      success: true,
      message: 'Account deletion initiated. This is a demo, so no actual deletion occurred.',
      warning: 'In production, this would delete all user data permanently.'
    });

  } catch (error) {
    console.error('Error deleting account:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
