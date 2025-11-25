import { NextRequest, NextResponse } from 'next/server';
import { getAPIKeys, createAPIKey, deleteAPIKey, checkAndUnlockAchievements } from '@/app/lib/db';
import crypto from 'crypto';

const DEFAULT_USER_ID = 'default_user';

/**
 * GET /api/api-keys
 * Get all API keys for current user
 */
export async function GET() {
  try {
    const keys = getAPIKeys(DEFAULT_USER_ID);

    return NextResponse.json({
      api_keys: keys.map((key: any) => ({
        key_id: key.key_id,
        name: key.name,
        key_preview: key.key_hash.substring(0, 12) + '...',
        created_at: key.created_at,
        last_used_at: key.last_used_at,
        status: key.status,
        requests_count: key.requests_count
      }))
    });

  } catch (error) {
    console.error('Error fetching API keys:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/api-keys
 * Create a new API key
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { name } = body;

    if (!name) {
      return NextResponse.json(
        { error: 'Name is required' },
        { status: 400 }
      );
    }

    // Generate API key
    const apiKey = 'tk_live_' + crypto.randomBytes(24).toString('hex');
    const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');

    // Store hashed version
    const keyId = createAPIKey(DEFAULT_USER_ID, name, keyHash);

    // Check for API developer achievement
    checkAndUnlockAchievements(DEFAULT_USER_ID);

    return NextResponse.json({
      key_id: keyId,
      api_key: apiKey, // Only returned once!
      name,
      message: 'API key created successfully. Make sure to copy it now, you won\'t see it again!'
    });

  } catch (error) {
    console.error('Error creating API key:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/api-keys
 * Delete an API key
 */
export async function DELETE(request: NextRequest) {
  try {
    const body = await request.json();
    const { key_id } = body;

    if (!key_id) {
      return NextResponse.json(
        { error: 'key_id is required' },
        { status: 400 }
      );
    }

    deleteAPIKey(key_id, DEFAULT_USER_ID);

    return NextResponse.json({
      success: true,
      message: 'API key deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting API key:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
