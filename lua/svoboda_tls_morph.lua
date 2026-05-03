-- PLGames Svoboda — TLS Morpher: pure-local TLS_INTERFERENCE primitive
--
-- Why:
--   When TSPU classifies a host as TLS_INTERFERENCE (curl exit=60), it
--   actively corrupts the TLS handshake mid-flight. Pure packet desync
--   (multisplit/multidisorder) sometimes works but often doesn't —
--   TSPU has gotten smarter about reassembly.
--
--   This primitive attacks the TSPU parser DIRECTLY at the TLS layer:
--   we fatten the ClientHello with RFC 7685 padding + GREASE extensions
--   until it's 2.5-4 KB. TSPU's stateful parser has a finite buffer.
--   Reseach (and field reports from RU community 2026) show that
--   ClientHello >2KB causes TSPU to either drop the connection (which
--   we detect and rotate) or — more often — give up on reassembly and
--   pass the traffic through uninspected.
--
--   Combined with multisplit, the now-huge CH gets split across MANY
--   TCP segments. TSPU has to reassemble every one before parsing.
--   Drop one segment in TSPU's view, the whole CH is unreadable to it.
--
-- This is "death by a thousand cuts" — purely local, no tunnel, no
-- proxy, no server cooperation. Just a fat TLS handshake that chokes
-- the middlebox.
--
-- Functions:
--   tls_pad        — add RFC 7685 padding extension (default 2048 bytes)
--   tls_extreorder — move SNI extension to end of list (parser confusion)
--   tls_grease     — add N GREASE-typed dummy extensions (RFC 8701)
--
-- Usage in flags:
--   --lua-desync=tls_pad
--   --lua-desync=tls_pad:size=4096
--   --lua-desync=tls_pad:size=2048:reorder=1:grease=4
--
-- Args (all optional):
--   size      = padding bytes (default 2048; TSPU buffer ~4KB so 2048 is safe)
--   reorder   = 1 to move SNI to end of extension list (default 0)
--   grease    = number of GREASE extensions to inject (default 0; 4 is sweet spot)


-- TLS padding extension (RFC 7685)
local _TLS_EXT_PADDING = 21

-- GREASE values (RFC 8701) — Chrome uses these to ensure middleboxes
-- ignore unknown extensions. TSPU parsers should tolerate them; if they
-- don't, parser bug → likely passes through.
local _GREASE_VALUES = {
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}


-- Internal: dissect TLS, run modify_fn on the ClientHello extensions
-- list, reconstruct, write back to desync.dis.payload. Returns true on
-- success, false on dissection failure.
local function _morph_client_hello(ctx, desync, modify_fn, log_label)
	if not desync.dis.tcp then
		if not desync.dis.icmp then instance_cutoff_shim(ctx, desync) end
		return false
	end
	if not direction_check(desync) or not payload_check(desync) then
		return false
	end
	if desync.l7payload ~= "tls_client_hello" then return false end

	local data = desync.reasm_data or desync.dis.payload
	if not data or #data == 0 then return false end

	local tdis = tls_dissect(data)
	if not tdis or not tdis.handshake or not tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT] then
		DLOG(log_label .. ": tls_dissect failed")
		return false
	end
	local hs = tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT]
	if not hs.dis or not hs.dis.ext then
		DLOG(log_label .. ": no extensions in ClientHello")
		return false
	end

	-- Run the actual mutation
	local before = #data
	modify_fn(hs.dis.ext)

	local rtls = tls_reconstruct(tdis)
	if not rtls then
		DLOG_ERR(log_label .. ": tls_reconstruct failed")
		return false
	end

	if b_debug then
		DLOG(log_label .. ": " .. before .. " -> " .. #rtls .. " bytes")
	end

	desync.dis.payload = rtls
	if desync.reasm_data then
		desync.reasm_data = rtls
	end
	return true
end


-- ── tls_pad ─────────────────────────────────────────────────────────────
--
-- Adds RFC 7685 padding extension stuffed with N zero bytes. TSPU's
-- stateful TLS parser has a finite reassembly buffer — Chromium adds
-- padding up to 256 bytes; we go much further (2KB default, configurable
-- to 4KB) to overflow the parser's expectation window. Server side just
-- skips padding (RFC-mandated), so no compat risk.
--
-- Bonus options:
--   reorder=1 → move SNI to end of extension list. Most parsers walk
--     extensions in order; if TSPU's parser gives up after N extensions
--     for performance, SNI never gets read.
--   grease=N → insert N RFC 8701 GREASE extensions with random reserved
--     types before padding. Adds further parser load.
function tls_pad(ctx, desync)
	local pad_size = tonumber(desync.arg.size) or 2048
	local do_reorder = (desync.arg.reorder == "1") or (desync.arg.reorder == true)
	local grease_count = tonumber(desync.arg.grease) or 0
	if pad_size < 0 then pad_size = 0 end
	if pad_size > 16000 then pad_size = 16000 end  -- TLS record max ~16KB

	_morph_client_hello(ctx, desync, function(ext_list)
		-- 1. Inject GREASE extensions before any modifications
		for i = 1, math.min(grease_count, #_GREASE_VALUES) do
			table.insert(ext_list, 1, {
				type = _GREASE_VALUES[i],
				data = "",  -- empty body; just the type counts
			})
		end

		-- 2. Reorder: move SNI to end if requested
		if do_reorder then
			local idx_sni = array_field_search(ext_list, "type", TLS_EXT_SERVER_NAME)
			if idx_sni then
				local sni = table.remove(ext_list, idx_sni)
				table.insert(ext_list, sni)
			end
		end

		-- 3. Add or augment padding extension (RFC 7685)
		local idx_pad = array_field_search(ext_list, "type", _TLS_EXT_PADDING)
		local padding_data = string.rep("\x00", pad_size)
		if idx_pad then
			-- replace existing padding
			ext_list[idx_pad].data = padding_data
			ext_list[idx_pad].dis = nil  -- force re-encode from .data
		else
			-- append new padding extension at end (where padding belongs)
			table.insert(ext_list, {
				type = _TLS_EXT_PADDING,
				data = padding_data,
			})
		end
	end, "tls_pad")
end


-- ── tls_extreorder ──────────────────────────────────────────────────────
--
-- Standalone extension-reorder primitive. Useful when we don't need
-- padding (latency-sensitive site) but still want to confuse TSPU's
-- order-dependent parser. Moves SNI to position N (default: end).
function tls_extreorder(ctx, desync)
	local target_pos = desync.arg.pos or "end"

	_morph_client_hello(ctx, desync, function(ext_list)
		local idx_sni = array_field_search(ext_list, "type", TLS_EXT_SERVER_NAME)
		if not idx_sni then return end
		local sni = table.remove(ext_list, idx_sni)
		if target_pos == "end" then
			table.insert(ext_list, sni)
		elseif target_pos == "start" then
			table.insert(ext_list, 1, sni)
		else
			local n = tonumber(target_pos) or #ext_list
			n = math.max(1, math.min(#ext_list + 1, n))
			table.insert(ext_list, n, sni)
		end
	end, "tls_extreorder")
end


-- ── tls_grease ──────────────────────────────────────────────────────────
--
-- Inject N RFC 8701 GREASE extensions to add parser load without
-- visible payload growth. Cheap defense against statistical fingerprinting
-- (each connection looks slightly different in extension types).
function tls_grease(ctx, desync)
	local count = tonumber(desync.arg.count) or 4
	count = math.max(1, math.min(count, #_GREASE_VALUES))

	_morph_client_hello(ctx, desync, function(ext_list)
		-- Random subset of GREASE values for diversity across calls
		local picks = {}
		for i = 1, #_GREASE_VALUES do picks[i] = i end
		-- Fisher-Yates shuffle (math.random ok here, lua VM uses time seed)
		for i = #picks, 2, -1 do
			local j = math.random(i)
			picks[i], picks[j] = picks[j], picks[i]
		end
		for i = 1, count do
			table.insert(ext_list, 1, {
				type = _GREASE_VALUES[picks[i]],
				data = "",
			})
		end
	end, "tls_grease")
end
