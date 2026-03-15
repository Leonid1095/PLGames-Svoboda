-- PLGames Svoboda — seed strategy: Rostelecom
-- ТСПУ: Эктако/Yadro v2 (TTL=53-58, win=0)

function sv_desync(conn)
    return {
        "--dpi-desync=disorder2",
        "--dpi-desync-ttl=5",
        "--dpi-desync-split-pos=3",
    }
end
