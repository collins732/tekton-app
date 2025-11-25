import { NextRequest, NextResponse } from 'next/server';
import { getAPIKeys, createAPIKey } from '../../lib/db';
import { getUserFromSession } from '../../lib/auth';
import crypto from 'crypto';

// GET - List all API keys for user
export async function GET() {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const keys = getAPIKeys(userId) as any[];

    // Calculate stats
    const totalKeys = keys.length;
    const activeKeys = keys.filter(k => k.status === 'active').length;
    const totalRequests = keys.reduce((sum, k) => sum + (k.requests_count || 0), 0);

    // Mask the key hashes for display
    const maskedKeys = keys.map(k => ({
      key_id: k.key_id,
      name: k.name,
      key_preview: 'tk_****' + k.key_hash.slice(-8),
      created_at: k.created_at,
      last_used_at: k.last_used_at,
      status: k.status,
      requests_count: k.requests_count || 0
    }));

    return NextResponse.json({
      keys: maskedKeys,
      stats: {
        total_keys: totalKeys,
        active_keys: activeKeys,
        total_requests: totalRequests
      }
    });
  } catch (error) {
    console.error('Error fetching API keys:', error);
    return NextResponse.json({ error: 'Failed to fetch API keys' }, { status: 500 });
  }
}

// POST - Create a new API key
export async function POST(request: NextRequest) {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const { name } = await request.json();

    if (!name || name.trim().length === 0) {
      return NextResponse.json({ error: 'Key name is required' }, { status: 400 });
    }

    // Generate a secure API key
    const rawKey = 'tk_live_' + crypto.randomBytes(24).toString('hex');

    // Store hashed version for security
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');

    const keyId = createAPIKey(userId, name.trim(), keyHash);

    return NextResponse.json({
      key_id: keyId,
      name: name.trim(),
      api_key: rawKey, // Only returned once at creation!
      message: 'API key created successfully. Store this key securely - it will not be shown again.'
    });
  } catch (error) {
    console.error('Error creating API key:', error);
    return NextResponse.json({ error: 'Failed to create API key' }, { status: 500 });
  }
}
