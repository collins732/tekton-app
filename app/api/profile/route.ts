import { NextRequest, NextResponse } from 'next/server';
import { getUser, updateUser } from '@/app/lib/db';
import { getUserFromSession } from '@/app/lib/auth';

/**
 * PATCH /api/profile
 * Update user profile (avatar, username, bio, country, social links)
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

    // Allowed profile fields
    const allowedFields = ['avatar', 'username', 'bio', 'country', 'github', 'twitter'];
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

    // Validate username if being updated
    if (updates.username) {
      if (updates.username.length < 3) {
        return NextResponse.json(
          { error: 'Username must be at least 3 characters' },
          { status: 400 }
        );
      }
    }

    updateUser(userId, updates);

    const updatedUser = getUser(userId) as any;

    return NextResponse.json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        avatar: updatedUser.avatar,
        username: updatedUser.username,
        bio: updatedUser.bio,
        country: updatedUser.country,
        github: updatedUser.github,
        twitter: updatedUser.twitter
      }
    });

  } catch (error) {
    console.error('Error updating profile:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
