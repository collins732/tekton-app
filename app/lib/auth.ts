import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import crypto from 'crypto';
import { createSessionInDb, getSessionFromDb, deleteSessionFromDb } from './db';

const SESSION_COOKIE_NAME = 'tekton_session';
const USER_ID_COOKIE_NAME = 'tekton_user_id';
const SESSION_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days

/**
 * Create a new session for a user
 */
export function createSession(userId: string): string {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + SESSION_DURATION;

  // Store session in database
  createSessionInDb(sessionId, userId, expiresAt);

  return sessionId;
}

/**
 * Get user ID from session cookie
 * Falls back to user_id cookie if session not found (for dev hot reload)
 */
export async function getUserFromSession(): Promise<string | null> {
  const cookieStore = await cookies();
  const sessionId = cookieStore.get(SESSION_COOKIE_NAME)?.value;

  if (sessionId) {
    // Get session from database
    const session = getSessionFromDb(sessionId);

    if (session) {
      return session.userId;
    }
  }

  // Fallback to user_id cookie (for dev hot reload persistence)
  const userIdCookie = cookieStore.get(USER_ID_COOKIE_NAME)?.value;
  if (userIdCookie && sessionId) {
    // Re-create session in database from cookie
    const expiresAt = Date.now() + SESSION_DURATION;
    createSessionInDb(sessionId, userIdCookie, expiresAt);
    return userIdCookie;
  }

  return null;
}

/**
 * Delete a session
 */
export function deleteSession(sessionId: string): void {
  deleteSessionFromDb(sessionId);
}

/**
 * Set session cookie in response
 */
export function setSessionCookie(response: NextResponse, sessionId: string, userId?: string): void {
  response.cookies.set(SESSION_COOKIE_NAME, sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: SESSION_DURATION / 1000, // in seconds
    path: '/'
  });

  // Also set user_id cookie for persistence (dev hot reload)
  if (userId) {
    response.cookies.set(USER_ID_COOKIE_NAME, userId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: SESSION_DURATION / 1000,
      path: '/'
    });
  }
}

/**
 * Clear session cookie
 */
export function clearSessionCookie(response: NextResponse): void {
  response.cookies.delete(SESSION_COOKIE_NAME);
  response.cookies.delete(USER_ID_COOKIE_NAME);
}

/**
 * Require authentication - throw error if not authenticated
 */
export async function requireAuth(): Promise<string> {
  const userId = await getUserFromSession();

  if (!userId) {
    throw new Error('Unauthorized');
  }

  return userId;
}
