# Blind tool-tiering annotation (held-out check of the tier tables)

The paper's tier tables (which tools are consequential and which of their arguments are key, designator or identifier
arguments) were written by the author. `tools_blind.csv` lists all 74 tools of the four AgentDojo suites with their
docstrings and parameter names and no tiering. An annotator who has NOT read the paper's tables fills the four `YOUR_*`
columns using only the definitions below, then `score.py` reports agreement with the author's tables.

Definitions (Sect. 4 of the paper):
- A tool is **consequential** if calling it sends, pays, deletes, publishes, shares, schedules or fetches from the outside world,
  i.e. it changes state that another party can observe or that cannot be undone by the agent; read-only tools are regular.
- **Key arguments** of a consequential tool are the parameters that determine who or what is affected.
- **Designator arguments** are key arguments that name a party or a place: recipients, e-mail and web addresses, account numbers, user names, channels.
- **Identifier arguments** are key arguments that carry a system-issued identifier: an event, file, e-mail or transaction id.
Parameters that are neither (amounts, dates, titles, passwords, text) are plain key arguments or not key at all.

Run: `python3 score.py tools_blind.csv` (keep the `suite` and `tool` columns unchanged). About two hours for 74 tools.
