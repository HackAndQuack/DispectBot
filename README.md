# DispectBot
A security Discord bot capable of:
- Automatic URL scanning (and deletion) using VirusTotal
- Host scanning through Shodan
- Reverse DNS lookups through Shodan
- Email notifications through emailrep
- Email address scanning through emailrep


# How this works
When a user sends a message into a Discord channel, this bot will look through the message for any URLs. 

If a URL exists in the sent message, the bot will scan it with [VirusTotal](https://www.virustotal.com/), delete the original message if malicious, and send a message to a logging channel. 

For non-automatic features, slash commands are being utilized through Discord. 

# Running on bare metal
1. (Optional) Create python virtual environment
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

# Running in Docker (recommended)
1. Build the container
```bash
docker build -t dispect .
```
2. Run the container
```bash
docker run --it dispect --channel <log_channel_id> --guild <discord_channel_id>
```

### NOTE:
The guild argument only exists so the bot can find the text channel to send logs to. The bot will still scan messages in all servers that its in, and send all logs from all servers to the specified channel. 

# Commands
| Command | Description |
| --- | ----------- |
| /urlscan | Scans a URL through VirusTotal. Enabling "verbose" will show exactly which antivirus engines returned what result. |
| /host_scan | Scans a hostname through Shodan |
| /api_info | Returns API credit information from Shodan |
| /email_scan | Gets e-mail reputation scan from emailrep |
| /getnews | Returns latest news from cybernews |

## License
This project is licensed under the MIT License

Copyright (c) 2023 Dispect_Devs