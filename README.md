# DispectBot
A security Discord bot capable of:
- Automatic URL scanning (and deletion) using VirusTotal
- Host scanning through Shodan
- Domain information through Shodan
- Reverse DNS lookups through Shodan
- Look up the IP address for the provided list of hostnames through Shodan
- Email reputation scan through emailrep
- Email address reporting through emailrep
- And much more!


# How this works
Dispect Bot comes with two types of functions automatic and non-automatic
# Automatic
When a user sends a message into a Discord channel, this bot will look through the message for any URLs. 

If a URL exists in the sent message, the bot will scan it with [VirusTotal](https://www.virustotal.com/), delete the original message if malicious, and send a message to a logging channel. 
# Non-Automatic
For non-automatic features, slash commands are being utilized through Discord. 

# Running on Docker (recommended)'
1. Pull the Docker image
```bash
docker pull ghcr.io/hackandquack/dispectbot:latest
```

2. Run the docker image
```bash
docker run --it dispectbot --log-channel <log_channel_id>\
    --guild <discord_guild_id>\
    --discord-token <discord_bot_token>\
    --shodan-token <shodan_token>\
    --emailrep-token <emailrep_token>\
    --virustotal-token <virustotal_token>
```

# Manually building and running Docker container 
1. After cloning this repository, build the container
```bash
docker build -t dispectbot .
```
2. Run the container
```bash
docker run --it dispectbot --log-channel <log_channel_id>\
    --guild <discord_guild_id>\
    --discord-token <discord_bot_token>\
    --shodan-token <shodan_token>\
    --emailrep-token <emailrep_token>\
    --virustotal-token <virustotal_token>
```

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
3. Run dispect.py
```bash
python dispect.py --log-channel <log_channel_id>\
    --guild <discord_guild_id>\
    --discord-token <discord_bot_token>\
    --shodan-token <shodan_token>\
    --emailrep-token <emailrep_token>\
    --virustotal-token <virustotal_token>
```

### NOTE:
The guild argument only exists so the bot can find the text channel to send logs to. The bot will still scan messages in all servers that its in, and send all logs from all servers to the specified channel. 

# Commands
| Command | Description |
| --- | ----------- |
| /urlscan | Scans a URL through VirusTotal. Enabling "verbose" will show exactly which antivirus engines returned what result. |
| /host_scan | Scans a hostname through Shodan |
| /dns_lookup | Look up the IP address for the provided list of hostnames
| /domain_infomation | Get all the subdomains and other DNS entries for the given domain. | |
| /reverse_dns | Look up the hostnames that have been defined for the given list of IP addresses |
| /api_info | Returns API credit information from Shodan |
| /email_scan | Gets e-mail reputation scan from emailrep |
| /report_email | Reports and email address |
| /get_report_tags | get tags to report an email address |
| /getnews | Returns latest news from cybernews |
| /threat_categories | Get a list of popular threat categories |

## License
This project is licensed under the MIT License

Copyright (c) 2023 Dispect_Devs