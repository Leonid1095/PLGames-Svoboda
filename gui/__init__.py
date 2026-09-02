"""PLGames Svoboda — desktop shell (PySide6/Qt).

A thin friendly frontend over the run_real.py engine. The GUI never runs DPI
desync itself: it launches run_real.py as the backend, reads live state from
runtime/status.json (see brain.status_writer), and guarantees cleanup on stop.
"""
