import discord 
from discord import app_commands
from dotenv import load_dotenv, find_dotenv
import pyfiglet
import os
import vt 
import json
import nest_asyncio
import argparse

# Set up argument parser
parser = argparse.ArgumentParser()
parser.add_argument('--channel', type=int, help='Channel ID for the bot to send analytics to', required=True)
parser.add_argument('--guild', type=int, help='Guild ID of the bot to use', required=True)
args = parser.parse_args()

nest_asyncio.apply()
load_dotenv()

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)
vt_client = vt.Client(os.getenv('VIRUS_TOTAL_API'))


# Slash command /getnews
@tree.command(name='getnews', description='gets the news')
async def getnews(interaction):
    await interaction.response.send_message('getting news!')


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
                analysis = vt_client.scan_url(word)
                while True:
                    analysis = vt_client.get_object("/analyses/{}", analysis.id)
                    print(f'Analysis status: {analysis.status}')
                    if analysis.status == "completed":
                        scan_result = str(analysis.get('results'))
                        break
                # Change every apostraphe to a quotation mark to convert the results to JSON 
                scan_result = scan_result.replace('\'', '"')
                # Parse JSON file to filter information
                scan_parsed = json.loads(scan_result)
                scan_list = list()
                for key in scan_parsed:
                    #print(f'{scan_parsed[key]["engine_name"]} result: {scan_parsed[key]["result"]}')
                    scan_list.append(f'{scan_parsed[key]["engine_name"]} result: {scan_parsed[key]["result"]}')

                # Sort scan_list based on severity
                scan_list_clean = list()
                scan_list_unrated = list()
                scan_list_malicious = list()
                scan_list_malware = list()
                for entry in scan_list:
                    if 'clean' in entry[entry.index(':'):]:
                        scan_list_clean.append(entry)
                    if 'unrated' in entry[entry.index(':'):]:
                        scan_list_unrated.append(entry)
                    if 'malicious' in entry[entry.index(':'):]:
                        scan_list_malicious.append(entry)
                    if 'malware' in entry[entry.index(':'):]:
                        scan_list_malware.append(entry)
                scan_list = list()
                for entry in scan_list_malware:
                    scan_list.append(entry)
                for entry in scan_list_malicious:
                    scan_list.append(entry)
                for entry in scan_list_unrated:
                    scan_list.append(entry)
                for entry in scan_list_clean:
                    scan_list.append(entry)

                # Format scan_list to string
                scan_str = ('Clean: ' + str(len(scan_list_clean)) + '(' + str((len(scan_list_clean)/len(scan_list))*100) +'%)'
                            + '\nUnrated: ' + str(len(scan_list_unrated)) + '(' + str((len(scan_list_unrated)/len(scan_list))*100) +'%)'
                            + '\nMalicious: ' + str(len(scan_list_malicious)) + '(' + str((len(scan_list_malicious)/len(scan_list))*100) +'%)'
                            + '\nMalware: ' + str(len(scan_list_malware)) + '(' + str((len(scan_list_malware)/len(scan_list))*100) +'%)'
                            + '\n' + ('-'*20) + '\n')
                
                for entry in scan_list:
                    if 'clean' in entry:
                        scan_str += ':white_check_mark: '
                    if 'unrated' in entry:
                        scan_str += ':grey_question: '
                    scan_str += entry + '\n'

                # Send embed message
                embed = discord.Embed(title=word, description=scan_str, color=0xFFFFFF)
                await log_channel.send(embed=embed)


client.run(os.getenv('DISCORD_BOT_TOKEN'))