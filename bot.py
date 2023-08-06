import discord 
from discord import app_commands
from dotenv import load_dotenv
import pyfiglet
import os
import argparse
from vtclient import *
from emailrepclient import *

# Set up argument parser
parser = argparse.ArgumentParser()
parser.add_argument('--channel', type=int, help='Channel ID for the bot to send analytics to', required=True)
parser.add_argument('--guild', type=int, help='Guild ID of the bot to use', required=True)
args = parser.parse_args()

load_dotenv()

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

# Slash command /report_email
#@tree.command(name='email_report', description='Report Email')
#async def report_email(ctx,email=''):
#   report_email(email)


@client.event
async def on_ready():
    await tree.sync()

    global guild
    guild = client.get_guild(args.guild)
    
    global log_channel
    log_channel = guild.get_channel(args.channel)

    print(pyfiglet.figlet_format('Dispect'))


@client.event
async def on_message(message):
    #Bot ignore itself
    if message.author == client.user:
        return
    
    if 'http' in message.content.lower():
        scan_result = ''
        message_parsed = message.content.split(' ')
        for word in message_parsed:
            if word.startswith('http'):
                print(f'Detected URL: {word}')
                # VirusTotal scan the URL, save results to scan_result
                scan_parsed = scan_for_json(word)
                # Parse through the dictionary
                scan_str = parse_and_sort(scan_parsed)
                # Send embed message
                embed = discord.Embed(title=word, description=scan_str, color=0xFFFFFF)
                await log_channel.send(embed=embed)

                if get_clean_percentage(scan_parsed) < 66:
                    await message.delete()


client.run(os.getenv('DISCORD_BOT_TOKEN'))