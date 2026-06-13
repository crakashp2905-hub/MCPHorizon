@echo off
REM Windows convenience shim: run the MCPHorizon CLI without installing.
REM Usage: mcphorizon scan <log>   |   mcphorizon check <events.json>   |   mcphorizon serve
python -m mcphorizon %*
