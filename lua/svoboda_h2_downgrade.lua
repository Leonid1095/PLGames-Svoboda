-- PLGames Svoboda — H2 downgrade primitive
--
-- New lua-desync function `alpn_strip` for forcing HTTP/1.1 fallback.
--
-- Why:
--   TSPU's HTTP2_STREAM_KILL pattern lets the TLS handshake complete
--   normally, then kills the HTTP/2 stream after a few KB. Pure packet
--   desync can't fix this — TLS already passed, the kill is at H2 layer.
--
-- How:
--   Strip h2 (and h2c) from the ALPN extension in TLS ClientHello.
--   Server falls back to HTTP/1.1, which TSPU does not stream-kill
--   on Discord/YouTube/etc.
--
-- Pipeline:
--   alpn_strip modifies desync.dis.payload in place, then the next
--   --lua-desync call (multisplit / multidisorder) splits/disorders
--   the modified ClientHello as usual. Combined effect: TSPU sees a
--   fragmented ClientHello with no h2 ALPN, server gets a clean
--   reassembled ClientHello with ALPN=[http/1.1].
--
-- Usage in flags:
--   --lua-desync=alpn_strip
--   --lua-desync=alpn_strip:strip=h2,h2c
--   --lua-desync=alpn_strip:strip=h2:keep_min=1
--
-- Args:
--   strip      = comma-separated ALPN protocols to remove (default: h2,h2c)
--   keep_min   = if removal would empty ALPN, ensure at least this many
--                http/1.1 entries remain (default: 1)


-- Modify TLS ClientHello payload in place: drop matching ALPN entries.
-- Does NOT send or drop the packet — leaves that to downstream desync
-- functions in the --lua-desync chain (multisplit, multidisorder, etc).
function alpn_strip(ctx, desync)
	-- Pass-through for non-TCP / non-TLS-handshake packets
	if not desync.dis.tcp then
		if not desync.dis.icmp then instance_cutoff_shim(ctx, desync) end
		return
	end
	-- Only act on outgoing TLS ClientHello
	if not direction_check(desync) or not payload_check(desync) then
		return
	end
	if desync.l7payload ~= "tls_client_hello" then
		return
	end

	local data = desync.reasm_data or desync.dis.payload
	if not data or #data == 0 then return end

	-- Dissect TLS handshake
	local tdis = tls_dissect(data)
	if not tdis or not tdis.handshake or not tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT] then
		DLOG("alpn_strip: tls_dissect failed (not a ClientHello?)")
		return
	end
	local hs = tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT]
	if not hs.dis or not hs.dis.ext then
		DLOG("alpn_strip: no extensions in ClientHello")
		return
	end

	-- Find ALPN extension
	local idx_alpn = array_field_search(hs.dis.ext, "type", TLS_EXT_ALPN)
	if not idx_alpn then
		DLOG("alpn_strip: no ALPN extension, nothing to strip")
		return
	end
	local alpn_list = hs.dis.ext[idx_alpn].dis and hs.dis.ext[idx_alpn].dis.list
	if not alpn_list then
		DLOG("alpn_strip: ALPN extension has no list")
		return
	end

	-- Build set of protocols to strip (default: h2 and h2c)
	local strip_arg = desync.arg.strip or "h2,h2c"
	local strip_set = {}
	for proto in string.gmatch(strip_arg, "[^,]+") do
		strip_set[proto] = true
	end

	-- Filter ALPN list
	local kept = {}
	local removed = 0
	for _, proto in ipairs(alpn_list) do
		if strip_set[proto] then
			removed = removed + 1
		else
			kept[#kept+1] = proto
		end
	end

	if removed == 0 then
		DLOG("alpn_strip: no matching protocols in ALPN, skipping")
		return
	end

	-- Ensure at least one fallback protocol survives so handshake doesn't fail
	local keep_min = tonumber(desync.arg.keep_min) or 1
	if #kept < keep_min then
		while #kept < keep_min do
			kept[#kept+1] = "http/1.1"
		end
	end
	hs.dis.ext[idx_alpn].dis.list = kept

	-- Reconstruct TLS payload
	local rtls = tls_reconstruct(tdis)
	if not rtls then
		DLOG_ERR("alpn_strip: tls_reconstruct failed")
		return
	end

	if b_debug then
		DLOG("alpn_strip: removed " .. removed .. " ALPN protocols, kept " .. #kept ..
		     " (payload " .. #data .. " -> " .. #rtls .. " bytes)")
	end

	-- In-place modification: subsequent --lua-desync calls in the chain
	-- (multisplit, multidisorder, fake) will see the new payload.
	desync.dis.payload = rtls
	if desync.reasm_data then
		desync.reasm_data = rtls
	end
end
