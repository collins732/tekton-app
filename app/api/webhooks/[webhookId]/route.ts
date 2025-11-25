import { NextRequest, NextResponse } from 'next/server';
import db from '../../../lib/db';
import { getUserFromSession } from '../../../lib/auth';

// DELETE - Delete a webhook
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ webhookId: string }> }
) {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const { webhookId } = await params;

    // Verify webhook belongs to user
    const stmt = db.prepare('SELECT * FROM webhooks WHERE webhook_id = ? AND user_id = ?');
    const webhook = stmt.get(webhookId, userId);

    if (!webhook) {
      return NextResponse.json({ error: 'Webhook not found' }, { status: 404 });
    }

    // Delete the webhook
    const deleteStmt = db.prepare('DELETE FROM webhooks WHERE webhook_id = ? AND user_id = ?');
    deleteStmt.run(webhookId, userId);

    return NextResponse.json({ message: 'Webhook deleted successfully' });
  } catch (error) {
    console.error('Error deleting webhook:', error);
    return NextResponse.json({ error: 'Failed to delete webhook' }, { status: 500 });
  }
}

// PUT - Update a webhook
export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ webhookId: string }> }
) {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const { webhookId } = await params;
    const { name, url, events, secret, status } = await request.json();

    // Verify webhook belongs to user
    const stmt = db.prepare('SELECT * FROM webhooks WHERE webhook_id = ? AND user_id = ?');
    const webhook = stmt.get(webhookId, userId);

    if (!webhook) {
      return NextResponse.json({ error: 'Webhook not found' }, { status: 404 });
    }

    // Build update query
    const updates: string[] = [];
    const values: any[] = [];

    if (name) {
      updates.push('name = ?');
      values.push(name.trim());
    }
    if (url) {
      updates.push('url = ?');
      values.push(url.trim());
    }
    if (events) {
      updates.push('events = ?');
      values.push(JSON.stringify(events));
    }
    if (secret !== undefined) {
      updates.push('secret = ?');
      values.push(secret || null);
    }
    if (status) {
      updates.push('status = ?');
      values.push(status);
    }

    if (updates.length === 0) {
      return NextResponse.json({ error: 'No fields to update' }, { status: 400 });
    }

    values.push(webhookId, userId);

    const updateStmt = db.prepare(`
      UPDATE webhooks SET ${updates.join(', ')} WHERE webhook_id = ? AND user_id = ?
    `);
    updateStmt.run(...values);

    return NextResponse.json({ message: 'Webhook updated successfully' });
  } catch (error) {
    console.error('Error updating webhook:', error);
    return NextResponse.json({ error: 'Failed to update webhook' }, { status: 500 });
  }
}

// POST - Test a webhook
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ webhookId: string }> }
) {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const { webhookId } = await params;

    // Verify webhook belongs to user
    const stmt = db.prepare('SELECT * FROM webhooks WHERE webhook_id = ? AND user_id = ?');
    const webhook = stmt.get(webhookId, userId) as any;

    if (!webhook) {
      return NextResponse.json({ error: 'Webhook not found' }, { status: 404 });
    }

    // Send test webhook
    const testPayload = {
      event: 'test',
      timestamp: Date.now(),
      data: {
        message: 'This is a test webhook from TEKTON',
        webhook_id: webhookId
      }
    };

    try {
      const response = await fetch(webhook.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Tekton-Event': 'test',
          'X-Tekton-Webhook-Id': webhookId
        },
        body: JSON.stringify(testPayload)
      });

      // Update last triggered
      const updateStmt = db.prepare('UPDATE webhooks SET last_triggered_at = ? WHERE webhook_id = ?');
      updateStmt.run(Date.now(), webhookId);

      return NextResponse.json({
        success: response.ok,
        status: response.status,
        message: response.ok ? 'Test webhook sent successfully' : `Webhook returned status ${response.status}`
      });
    } catch (fetchError) {
      return NextResponse.json({
        success: false,
        message: 'Failed to reach webhook URL'
      });
    }
  } catch (error) {
    console.error('Error testing webhook:', error);
    return NextResponse.json({ error: 'Failed to test webhook' }, { status: 500 });
  }
}
