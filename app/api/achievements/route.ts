import { NextResponse } from 'next/server';
import { getUserAchievements } from '@/app/lib/db';
import { getUserFromSession } from '@/app/lib/auth';

/**
 * GET /api/achievements
 * Get all achievements with unlock status
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

    const achievements = getUserAchievements(userId);

    return NextResponse.json(
      achievements.map((a: any) => ({
        achievement_id: a.achievement_id,
        name: a.name,
        description: a.description,
        icon: a.icon,
        rarity: a.rarity,
        points: a.points,
        unlocked: !!a.unlocked_at,
        unlocked_at: a.unlocked_at
      }))
    );

  } catch (error) {
    console.error('Error fetching achievements:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
