import discord 
from discord import app_commands
import pyfiglet
import argparse
from vtclient import *
from emailrepclient import *
from shodanclient import *


# Set up argument parser
parser = argparse.ArgumentParser()
parser.add_argument('-lc', '--log-channel', type=int, help='Channel ID for the bot to send analytics to', required=True)
parser.add_argument('-g', '--guild', type=int, help='Guild ID of the bot to use', required=True)
parser.add_argument('-dt', '--discord-token', type=str, help='Discord bot token', required=True)
parser.add_argument('-st', '--shodan-token', type=str, help='Shodan API token', required=True)
parser.add_argument('-et', '--emailrep-token', type=str, help='Emailrep API token', required=True)
parser.add_argument('-vt', '--virustotal-token', type=str, help='VirusTotal API token', required=True)

args = parser.parse_args()

# Initialize other APIs
set_shodan_token(args.shodan_token)
set_emailrep_token(args.emailrep_token)
set_vt_token(args.virustotal_token)

# Initialize Discord bot
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

# Slash command /getnews
@tree.command(name='getnews', description='gets the news')
async def getnews(interaction):
    await interaction.response.send_message('getting news!')


# Slash command /get_email
@tree.command(name='email_scan', description='Scans Email')
async def get_email(ctx, email:str):
    email_response = scan_email(email)
    embed = discord.Embed(title='Email Response', description=email_response, color=0x00FFF)
    await ctx.response.send_message(embed=embed)

# Slash command /report_email <email> [tags] <reason>
@tree.command(name='report_email', description='Reports an email address')
async def report_email(ctx, email:str, tags:str, reason:str):
    tags = tags.split()
    report_response = report_email(email,tags,reason)
    embed = discord.Embed(title='Report Email', description=report_response, color=0xffc87c)
    await ctx.response.send_message(embed=embed)

# Slash command /get_report_tags to view what tags a user can add
@tree.command(name='get_report_tags', description='Get tags to report an email address')
async def get_report_tags(ctx):
    tag_response = show_tags()
    embed = discord.Embed(title='Report Tags', description=tag_response, color=0xff2400)
    await ctx.response.send_message(embed=embed)


# Slash command /api_info 
@tree.command(name='api_info', description='Returns information about the API plan belonging to the given API key')
async def api_info(ctx):
    print("Getting API Info")
    api_reponse = get_api_info()
    embed = discord.Embed(title=('API Info'), description=api_reponse, color=0x2fd76b)
    await ctx.response.send_message(embed=embed)

# Slash command /host_scan <ip_address>
@tree.command(name='host_scan', description='Returns all services that have been found on the given host IP')
async def host_scan(ctx, ip:str):
    if(check(ip) == True):
        ip_response = scan_host(ip)
        embed = discord.Embed(title=('Host Scan for ' + str(ip)), description=ip_response, color=0x00ff00)
        await ctx.response.send_message(embed=embed)
    #Reports to user when IP address is wrong
    else:
        embed = discord.Embed(title=('Not a Valid IP: ' + str(ip) + "!"), description="Please enter a valid IP address https://en.wikipedia.org/wiki/IP_address", color=0xff0000)
        await ctx.response.send_message(embed=embed)

# Slash command /domain_infomation <domain_name>]
@tree.command(name='domain_information',description='Get all the subdomains and other DNS entries for the given domain. Uses 1 query credit per lookup')
async def domain_information(ctx, domain:str):
    domain_information_response = domain_information(domain)
    embed = discord.Embed(title=('Domain Information for ' + str(domain)), description=domain_information_response, color=0x80FF00)
    await ctx.response.send_message(embed=embed)  

# Slash command /dns_lookup [host_name's]
@tree.command(name='dns_lookup', description='Look up the IP address for the provided list of hostnames.')
async def dns_lookup(ctx, host_names:str):
    dns_lookup_response = dns_lookup_info(host_names)
    embed = discord.Embed(title=('DNS Lookup for ' + str(host_names)), description=dns_lookup_response, color=0xFFC0CB)
    await ctx.response.send_message(embed=embed)  
    
# Slash command /reverse_dns [ip_address's]
@tree.command(name='reverse_dns', description='Look up the hostnames that have been defined for the given list of IP addresses.')
async def reverse_dns(ctx,ips:str):
    dns_response = reverse_dns_info(ips)
    embed = discord.Embed(title=('DNS Scans for ' + str(ips)), description=dns_response, color=0xFFC0CB)
    await ctx.response.send_message(embed=embed)


# Slash command /urlscan <url> <True/False>
@tree.command(name='urlscan', description='Scans a URL manually')
async def urlscan(ctx, url:str, verbose:bool):
    try:
        scan_parsed = scan_for_json(url)
        scan_str = parse_and_sort(scan_parsed, verbose)
        embed = discord.Embed(title=url, description=scan_str, color=0x0000FF)
        embed.set_footer(text='Results come from VirusTotal.com', icon_url='https://cdn.icon-icons.com/icons2/2699/PNG/512/virustotal_logo_icon_171247.png')
        await ctx.response.send_message(embed=embed)
    except:
        await ctx.response.send_message('Error occured, try again (is the URL valid?)')

# Slash command /threat_categories
@tree.command(name='threat_categories', description='Get a list of popular threat categories')
async def threat_categories(ctx):
    threat_categories_parsed = get_threat_categories()
    embed = discord.Embed(title='Threat Categories', description=threat_categories_parsed, color=0x800080)
    await ctx.response.send_message(embed=embed)

# Sets activity
@client.event
async def on_ready():
    await tree.sync()
    await client.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name='for malware'))

    global guild
    guild = client.get_guild(args.guild)
    
    global log_channel
    log_channel = guild.get_channel(args.log_channel)

    print(pyfiglet.figlet_format('Dispect'))


@client.event
async def on_message(message):
    #Bot ignore itself
    if message.author == client.user:
        return
    #Detects if user sends a URL
    if 'http' in message.content.lower():
        scan_result = ''
        message_parsed = message.content.split(' ')
        for word in message_parsed:
            if word.startswith('http'):
                print(f'Detected URL: {word}')
                # VirusTotal scan the URL, save results to scan_result
                scan_parsed = scan_for_json(word)
                # Parse through the dictionary
                scan_str = parse_and_sort(scan_parsed, True)
                # Send embed message
                embed = discord.Embed(title=word, description=scan_str, color=0x0000FF)
                embed.set_footer(text='Results come from VirusTotal.com\nURL sent by ' + message.author.name + ' (' + message.author.mention + ')', icon_url='https://cdn.icon-icons.com/icons2/2699/PNG/512/virustotal_logo_icon_171247.png')
                await log_channel.send(embed=embed)

                if get_clean_percentage(scan_parsed) < 66:
                    await message.delete()


client.run(args.discord_token)