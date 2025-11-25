import { NextRequest, NextResponse } from 'next/server';
import { getUserFromSession } from '@/app/lib/auth';

const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID || '';
const GITHUB_REDIRECT_URI = process.env.GITHUB_REDIRECT_URI || 'http://localhost:3000/api/github/callback';

/**
 * GET /api/github/auth
 * Redirect to GitHub OAuth authorization
 */
export async function GET() {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.redirect(new URL('/login', process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'));
    }

    if (!GITHUB_CLIENT_ID) {
      return NextResponse.json(
        { error: 'GitHub OAuth not configured. Please set GITHUB_CLIENT_ID in environment variables.' },
        { status: 500 }
      );
    }

    // GitHub OAuth scopes needed
    const scopes = ['read:user', 'user:email', 'repo'].join(' ');

    // State parameter for security (includes user ID)
    const state = Buffer.from(JSON.stringify({ userId, timestamp: Date.now() })).toString('base64');

    const authUrl = new URL('https://github.com/login/oauth/authorize');
    authUrl.searchParams.set('client_id', GITHUB_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', GITHUB_REDIRECT_URI);
    authUrl.searchParams.set('scope', scopes);
    authUrl.searchParams.set('state', state);

    return NextResponse.redirect(authUrl.toString());
  } catch (error) {
    console.error('GitHub auth error:', error);
    return NextResponse.json({ error: 'Failed to initiate GitHub auth' }, { status: 500 });
  }
}
