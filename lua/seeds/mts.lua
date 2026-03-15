-- PLGames Svoboda — seed strategy: MTS
-- ТСПУ: varies by region

function sv_desync(conn)
    return {
        "--dpi-desync=multisplit",
        "--dpi-desync-fooling=badseq",
        "--dpi-desync-ttl=8",
    }
end
