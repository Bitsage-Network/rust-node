-- Add new trading pair with real STRK token (pair_id 1)
INSERT INTO trading_pairs (
    pair_id, 
    base_token, 
    quote_token, 
    base_symbol, 
    quote_symbol, 
    min_order_size, 
    tick_size,
    maker_fee_bps, 
    taker_fee_bps,
    is_active
) VALUES (
    1,
    '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850', -- SAGE
    '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d', -- Real STRK
    'SAGE',
    'STRK',
    1000000000000000000,  -- 1 SAGE minimum
    100000000000000,       -- 0.0001 STRK tick size
    10,   -- 0.1% maker fee
    30,   -- 0.3% taker fee
    true
) ON CONFLICT (pair_id) DO UPDATE SET
    quote_token = EXCLUDED.quote_token,
    tick_size = EXCLUDED.tick_size,
    is_active = EXCLUDED.is_active;

-- Also update pair_id 0 to mark as inactive (uses mock STRK)
UPDATE trading_pairs SET is_active = false WHERE pair_id = 0;

SELECT pair_id, quote_token, is_active FROM trading_pairs ORDER BY pair_id;
