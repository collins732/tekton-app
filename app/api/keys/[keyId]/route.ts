import { NextRequest, NextResponse } from 'next/server';
import db from '../../../lib/db';
import { getUserFromSession } from '../../../lib/auth';
import crypto from 'crypto';

// DELETE - Revoke an API key
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ keyId: string }> }
) {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const { keyId } = await params;

    // Verify key belongs to user
    const stmt = db.prepare('SELECT * FROM api_keys WHERE key_id = ? AND user_id = ?');
    const key = stmt.get(keyId, userId);

    if (!key) {
      return NextResponse.json({ error: 'API key not found' }, { status: 404 });
    }

    // Delete the key
    const deleteStmt = db.prepare('DELETE FROM api_keys WHERE key_id = ? AND user_id = ?');
    deleteStmt.run(keyId, userId);

    return NextResponse.json({ message: 'API key revoked successfully' });
  } catch (error) {
    console.error('Error revoking API key:', error);
    return NextResponse.json({ error: 'Failed to revoke API key' }, { status: 500 });
  }
}

// PUT - Regenerate an API key
export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ keyId: string }> }
) {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const { keyId } = await params;

    // Verify key belongs to user
    const stmt = db.prepare('SELECT * FROM api_keys WHERE key_id = ? AND user_id = ?');
    const key = stmt.get(keyId, userId) as any;

    if (!key) {
      return NextResponse.json({ error: 'API key not found' }, { status: 404 });
    }

    // Generate a new API key
    const rawKey = 'tk_live_' + crypto.randomBytes(24).toString('hex');
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');

    // Update the key
    const updateStmt = db.prepare(`
      UPDATE api_keys
      SET key_hash = ?, last_used_at = NULL, requests_count = 0
      WHERE key_id = ? AND user_id = ?
    `);
    updateStmt.run(keyHash, keyId, userId);

    return NextResponse.json({
      key_id: keyId,
      name: key.name,
      api_key: rawKey, // Only returned once!
      message: 'API key regenerated successfully. Store this key securely - it will not be shown again.'
    });
  } catch (error) {
    console.error('Error regenerating API key:', error);
    return NextResponse.json({ error: 'Failed to regenerate API key' }, { status: 500 });
  }
}

// PATCH - Update key status (activate/deactivate)
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ keyId: string }> }
) {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const { keyId } = await params;
    const { status } = await request.json();

    if (!['active', 'inactive'].includes(status)) {
      return NextResponse.json({ error: 'Invalid status' }, { status: 400 });
    }

    // Verify key belongs to user
    const stmt = db.prepare('SELECT * FROM api_keys WHERE key_id = ? AND user_id = ?');
    const key = stmt.get(keyId, userId);

    if (!key) {
      return NextResponse.json({ error: 'API key not found' }, { status: 404 });
    }

    // Update status
    const updateStmt = db.prepare('UPDATE api_keys SET status = ? WHERE key_id = ? AND user_id = ?');
    updateStmt.run(status, keyId, userId);

    return NextResponse.json({ message: `API key ${status === 'active' ? 'activated' : 'deactivated'} successfully` });
  } catch (error) {
    console.error('Error updating API key status:', error);
    return NextResponse.json({ error: 'Failed to update API key status' }, { status: 500 });
  }
}
