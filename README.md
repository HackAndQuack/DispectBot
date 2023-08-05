# DispectBot
A Discord bot capable of evaluating and responding to URL uploads that have malicious intent.

# How this works
When a user sends a message into a Discord channel, this bot will look through the message for any URLs. 

If a URL exists in the sent message, the bot will scan it with [VirusTotal](https://www.virustotal.com/), delete the original message if malicious, and send a message to a logging channel. 

# Usage
1. (Optional) create python virtual environment
```bash
python -m venv .venv
source .venv/bin/activate
```
2. Install requirements
```bash
pip install -r requirements.txt
```
3. Run bot.py
```bash
python bot.py --channel <log_channel_id> --guild <discord_guild_id>
```