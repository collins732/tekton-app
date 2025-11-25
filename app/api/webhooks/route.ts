import { NextRequest, NextResponse } from 'next/server';
import { getWebhooks, createWebhook, deleteWebhook } from '@/app/lib/db';
import { getUserFromSession } from '@/app/lib/auth';

/**
 * GET /api/webhooks
 * Get all webhooks for current user
 */
export async function GET() {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const webhooks = getWebhooks(userId);

    return NextResponse.json({
      webhooks,
      count: webhooks.length
    });

  } catch (error) {
    console.error('Error fetching webhooks:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/webhooks
 * Create a new webhook
 */
export async function POST(request: NextRequest) {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const body = await request.json();
    const { name, url, events, secret } = body;

    if (!name || !url || !events) {
      return NextResponse.json(
        { error: 'name, url, and events are required' },
        { status: 400 }
      );
    }

    // Validate URL
    try {
      new URL(url);
    } catch {
      return NextResponse.json({ error: 'Invalid URL format' }, { status: 400 });
    }

    const webhookId = createWebhook(userId, { name, url, events, secret });

    return NextResponse.json({
      success: true,
      webhook_id: webhookId,
      message: 'Webhook created successfully'
    });

  } catch (error) {
    console.error('Error creating webhook:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/webhooks
 * Delete a webhook
 */
export async function DELETE(request: NextRequest) {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const body = await request.json();
    const { webhook_id } = body;

    if (!webhook_id) {
      return NextResponse.json(
        { error: 'webhook_id is required' },
        { status: 400 }
      );
    }

    deleteWebhook(webhook_id, userId);

    return NextResponse.json({
      success: true,
      message: 'Webhook deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting webhook:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
