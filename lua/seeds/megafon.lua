-- PLGames Svoboda — seed strategy: Megafon
-- ТСПУ: varies by region

function sv_desync(conn)
    return {
        "--dpi-desync=fake",
        "--dpi-desync-ipfrag=1",
        "--dpi-desync-ttl=6",
    }
end
