import { NextRequest, NextResponse } from 'next/server';
import { createTokenPurchase, getUser } from '@/app/lib/db';
import { getUserFromSession } from '@/app/lib/auth';

/**
 * POST /api/tokens/purchase
 * Purchase tokens (simulated - no real payment)
 */
export async function POST(request: NextRequest) {
  try {
    // Get authenticated user
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized. Please login first.' },
        { status: 401 }
      );
    }

    const body = await request.json();
    const { tokens, price, paymentMethod } = body;

    // Validate input
    if (!tokens || !price || tokens <= 0 || price <= 0) {
      return NextResponse.json(
        { error: 'Invalid tokens or price' },
        { status: 400 }
      );
    }

    // Simulate purchase (in real app, this would call payment gateway)
    const purchaseId = createTokenPurchase(
      userId,
      1, // quantity (always 1 pack)
      tokens,
      parseFloat(price),
      paymentMethod || 'demo'
    );

    // Get updated user data
    const user = getUser(userId) as any;

    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      );
    }

    return NextResponse.json({
      success: true,
      purchase_id: purchaseId,
      tokens_added: tokens,
      new_balance: user.tokens,
      message: `Successfully purchased ${tokens} tokens!`
    });

  } catch (error) {
    console.error('Error purchasing tokens:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
