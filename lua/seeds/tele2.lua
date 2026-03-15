-- PLGames Svoboda — seed strategy: Tele2
-- ТСПУ: varies by region

function sv_desync(conn)
    return {
        "--dpi-desync=overlap",
        "--dpi-desync-fooling=badsum",
        "--dpi-desync-ttl=4",
    }
end
