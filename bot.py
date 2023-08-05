import discord 
from discord import app_commands
from dotenv import load_dotenv, find_dotenv
import pyfiglet
import os
import vt 
import json
import nest_asyncio
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
    print(pyfiglet.figlet_format('Dispect'))

@client.event
async def on_message(message):
    #Bot ignore itself
    if message.author == client.user:
        return
    
    if 'http' in message.content.lower():
        url = ''
        data = ''
        message_parsed = message.content.split(' ')
        for word in message_parsed:
            if word.startswith('http'):
                print('Thats a URL!')
                url = word
                analysis = vt_client.scan_url(url)
                while True:
                    analysis = vt_client.get_object("/analyses/{}", analysis.id)
                    print(analysis.status)
                    if analysis.status == "completed":
                        print(analysis.get('results'))
                        print(type(analysis.get('results')))
                        break
                    

client.run(os.getenv('DISCORD_BOT_TOKEN'))