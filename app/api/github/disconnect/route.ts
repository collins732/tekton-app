import { NextRequest, NextResponse } from 'next/server';
import { getUserFromSession } from '@/app/lib/auth';
import { getIntegrations, deleteIntegration } from '@/app/lib/db';

/**
 * POST /api/github/disconnect
 * Disconnect GitHub integration
 */
export async function POST() {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    // Get GitHub integration
    const integrations = getIntegrations(userId) as any[];
    const githubIntegration = integrations.find(i => i.service === 'github');

    if (!githubIntegration) {
      return NextResponse.json({ error: 'GitHub not connected' }, { status: 400 });
    }

    // Delete integration
    deleteIntegration(githubIntegration.integration_id, userId);

    return NextResponse.json({
      success: true,
      message: 'GitHub disconnected successfully'
    });
  } catch (error) {
    console.error('Error disconnecting GitHub:', error);
    return NextResponse.json({ error: 'Failed to disconnect GitHub' }, { status: 500 });
  }
}
