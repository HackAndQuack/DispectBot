import discord
from discord.ext import app_commands
from dotenv import load_dotenv, find_dotenv
import pyfiglet
import os

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)


# Slash command /getnews
@tree.command(name='getnews', description='gets the news')
async def getnews(interaction):
    await interaction.response.send_message('getting news!')


@client.event
async def on_ready():
    await tree.sync()
    print(pyfiglet.figlet_format('Dispect'))


load_dotenv()
client.run(os.getenv('DISCORD_BOT_TOKEN'))