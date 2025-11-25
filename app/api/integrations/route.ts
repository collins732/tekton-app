import { NextRequest, NextResponse } from 'next/server';
import { getIntegrations, createIntegration, deleteIntegration } from '@/app/lib/db';
import { getUserFromSession } from '@/app/lib/auth';

/**
 * GET /api/integrations
 * Get all integrations for current user
 */
export async function GET() {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const integrations = getIntegrations(userId);

    return NextResponse.json({
      integrations,
      count: integrations.length
    });

  } catch (error) {
    console.error('Error fetching integrations:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/integrations
 * Connect a new integration
 */
export async function POST(request: NextRequest) {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const body = await request.json();
    const { service, config } = body;

    if (!service) {
      return NextResponse.json(
        { error: 'Service is required' },
        { status: 400 }
      );
    }

    // Check if already connected
    const existing = getIntegrations(userId) as any[];
    if (existing.some(i => i.service === service)) {
      return NextResponse.json(
        { error: 'Integration already connected' },
        { status: 400 }
      );
    }

    const integrationId = createIntegration(userId, service, config || {});

    return NextResponse.json({
      success: true,
      integration_id: integrationId,
      message: `${service} connected successfully`
    });

  } catch (error) {
    console.error('Error creating integration:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/integrations
 * Disconnect an integration
 */
export async function DELETE(request: NextRequest) {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const body = await request.json();
    const { integration_id } = body;

    if (!integration_id) {
      return NextResponse.json(
        { error: 'integration_id is required' },
        { status: 400 }
      );
    }

    deleteIntegration(integration_id, userId);

    return NextResponse.json({
      success: true,
      message: 'Integration disconnected successfully'
    });

  } catch (error) {
    console.error('Error deleting integration:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * PATCH /api/integrations
 * Update integration config
 */
export async function PATCH(request: NextRequest) {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const body = await request.json();
    const { integration_id, config } = body;

    if (!integration_id || !config) {
      return NextResponse.json(
        { error: 'integration_id and config are required' },
        { status: 400 }
      );
    }

    // Import db directly for update
    const db = (await import('@/app/lib/db')).default;
    const stmt = db.prepare('UPDATE integrations SET config = ? WHERE integration_id = ? AND user_id = ?');
    stmt.run(JSON.stringify(config), integration_id, userId);

    return NextResponse.json({
      success: true,
      message: 'Integration updated successfully'
    });

  } catch (error) {
    console.error('Error updating integration:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
