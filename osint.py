import os
import dns.resolver
from dotenv import load_dotenv  # <-- 1. This is crucial for loading the .env file
from telegram import Update
from telegram import Update, BotCommand
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
import nvdlib
import logging
import requests
# --- SETUP LOGGING ---
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# --- LOAD TOKEN ---
load_dotenv()  # <-- Must be called to load variables from .env
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") 

if not TOKEN:
    print("FATAL ERROR: TELEGRAM_BOT_TOKEN not found. Check your .env file.")
    exit()

# --- UTILITY FUNCTIONS ---

def perform_dns_lookup(domain: str) -> str:
    """Performs DNS lookups for A, MX, NS, and TXT records."""
    results = []
    record_types = ['A', 'MX', 'NS', 'TXT']
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            result = f"**{rtype} Records:**\n"
            for rdata in answers:
                if rtype == 'MX':
                    result += f"  - Preference: {rdata.preference}, Host: `{rdata.exchange}`\n"
                elif rtype == 'TXT':
                    txt_value = rdata.strings[0].decode().strip('"') 
                    result += f"  - `{txt_value}`\n"
                else:
                    result += f"  - `{rdata.to_text()}`\n"
            results.append(result)

        except dns.resolver.NoAnswer:
            results.append(f"**{rtype} Records:** No record found.")
        except dns.resolver.NXDOMAIN:
            return f"Error: Domain `{domain}` does not exist (NXDOMAIN)."
        except dns.exception.Timeout:
            return f"Error: DNS query timed out for `{domain}`."
        except Exception as e:
            results.append(f"Error during {rtype} lookup: {e}")

    return "\n".join(results)

def perform_cve_lookup(cve_id: str) -> str:
    """Fetches details for a specific CVE ID using nvdlib."""
    try:
        results = nvdlib.searchCVE(cveId=cve_id) 

        if not results:
            return f"**CVE ID:** `{cve_id}` was not found in the NVD."

        cve = results[0]
        description = cve.descriptions[0].value
        cvss_v3_score = getattr(cve, 'v31score', 'N/A')
        cvss_v3_severity = getattr(cve, 'v31severity', 'N/A')
        
        output = f"**🚨 CVE Details: {cve.id}**\n"
        output += f"**Severity (CVSS 3.1):** {cvss_v3_severity}\n"
        output += f"**Score:** `{cvss_v3_score}`\n"
        output += f"**Description:** {description}\n"
        output += f"\n**Published:** {cve.published}\n"
        output += f"**NVD Link:** [View Details](https://nvd.nist.gov/vuln/detail/{cve.id})"
        
        return output

    except Exception as e:
        if "rate limit" in str(e).lower():
            return "Error: NVD API rate limit reached. Please wait a few seconds and try again."
        return f"An unexpected error occurred during CVE lookup: {e}"
    
# --- UTILITY FUNCTIONS ---
# ... (perform_dns_lookup and perform_cve_lookup go here) ...

def perform_geoip_lookup(target: str) -> str:
    """Fetches GeoIP details for an IP or domain using the ip-api.com service."""
    # ip-api.com automatically handles domains by resolving them to an IP first
    API_URL = f"http://ip-api.com/json/{target}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query"
    
    try:
        response = requests.get(API_URL, timeout=5)
        response.raise_for_status() # Raises an HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        if data.get("status") == "fail":
            return f"Error: GeoIP lookup failed. Reason: {data.get('message', 'Unknown failure.')}"
        
        if data.get("status") != "success":
            return f"Error: GeoIP lookup failed with status: {data.get('status')}."

        # Successful lookup - format the result
        output = f"**📍 GeoIP Analysis for:** `{data.get('query', target)}`\n"
        output += f"**ISP/Organization:** {data.get('isp', 'N/A')} / {data.get('org', 'N/A')}\n"
        output += f"**ASN:** `{data.get('as', 'N/A')}`\n"
        output += f"**Location:** {data.get('city', 'N/A')}, {data.get('regionName', 'N/A')}, {data.get('country', 'N/A')} ({data.get('zip', 'N/A')})\n"
        output += f"**Coordinates:** Lat: `{data.get('lat', 'N/A')}`, Lon: `{data.get('lon', 'N/A')}`\n"
        
        # Add Google Maps link for easy visualization
        if data.get('lat') and data.get('lon'):
             output += f"\n[View Map Location](http://www.google.com/maps/search/?api=1&query={data['lat']},{data['lon']})"
        
        return output

    except requests.exceptions.Timeout:
        return "Error: GeoIP query timed out. The API took too long to respond."
    except requests.exceptions.RequestException as e:
        return f"Error during GeoIP API request: {e}"
    except Exception as e:
        return f"An unexpected error occurred during GeoIP lookup: {e}"

# ... rest of your utility functions ...    

# --- UTILITY FUNCTIONS ---
# ... (all other utility functions go here) ...

def perform_username_check(username: str) -> str:
    """
    Checks the given username across high-value social media platforms
    by analyzing the response content using a persistent requests Session.
    """
    
    # Define sites, the URL format, and the text that confirms the profile DOES NOT exist.
    SOCIAL_MEDIA_SITES = [
        {"name": "Twitter/X", "url": f"https://x.com/{username}", "not_found_text": 'Page not found'},
        {"name": "Instagram", "url": f"https://instagram.com/{username}", "not_found_text": 'Page Not Found'},
        {"name": "TikTok", "url": f"https://www.tiktok.com/@{username}", "not_found_text": 'couldn\'t find this account'},
        {"name": "GitHub", "url": f"https://github.com/{username}", "not_found_text": 'Not Found'},
        {"name": "Reddit", "url": f"https://www.reddit.com/user/{username}", "not_found_text": 'the page may have been removed'},
    ]
    
    found_profiles = []
    
    # Define session headers once
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' # Add Accept header for realism
    }

    # Use a requests.Session for persistent connections and header management
    with requests.Session() as session:
        session.headers.update(headers)

        for site in SOCIAL_MEDIA_SITES:
            url = site["url"]
            not_found_text = site["not_found_text"]
            site_name = site["name"]

            try:
                # Use the session object for the request
                response = session.get(url, timeout=10, allow_redirects=True)
                
                # Check for client/server errors first
                response.raise_for_status()

                # Check if the 'Not Found' text is NOT in the response content (case-insensitive)
                # and that the status is generally acceptable.
                if not not_found_text.lower() in response.text.lower():
                    # If we made it here, it's a potential hit!
                    found_profiles.append(f"• <b>{site_name}</b>: <a href='{url}'>Found Profile</a>")
                
            except requests.exceptions.HTTPError:
                # Handle 4xx/5xx errors (likely Not Found or Blocked)
                continue
            except requests.exceptions.RequestException:
                # Catch all other network errors (Timeout, ConnectionError, etc.)
                continue
            except Exception:
                # Catch any final unexpected error and move on.
                continue

    # --- Format the output ---
    output = f"<b>👤 Username Check for:</b> <code>{username}</code>\n\n"
    
    if found_profiles:
        output += f"<b>✅ {len(found_profiles)} Profiles Found:</b>\n"
        output += "\n".join(found_profiles)
    else:
        output += "❌ <b>No profiles found</b> for this username on the sites checked."
        output += "\n\n(Note: Results rely on site response indicators and may not be 100% conclusive.)"

    return output

# ... rest of your utility functions ...

# --- UTILITY FUNCTIONS ---
# ... (perform_dns_lookup, perform_cve_lookup, perform_geoip_lookup, perform_username_check go here) ...

def perform_subdomain_enum(domain: str) -> str:
    """
    Fetches subdomains for a given domain using the crt.sh certificate transparency logs API.
    """
    # crt.sh query format: ?q=%.<domain>&output=json
    API_URL = f"https://crt.sh/?q=%.{domain}&output=json"
    
    # We use a set to automatically handle duplicate subdomains
    subdomains = set()

    try:
        # Use a realistic User-Agent just in case
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(API_URL, headers=headers, timeout=15)
        response.raise_for_status() # Raise an exception for bad status codes
        
        # The response is a JSON array of certificate objects
        data = response.json()
        
        if not data:
            return f"❌ **No subdomains found** in Certificate Transparency logs for `{domain}`."

        for cert in data:
            # We are interested in the 'name_value' field, which contains the domain/subdomain
            name_value = cert.get("name_value", "")
            
            # The name_value often contains multiple domains separated by newlines
            domains_list = name_value.split('\n')
            
            for d in domains_list:
                d = d.strip().lower()
                # Filter out the base domain and wildcards (*.)
                if d.endswith(f".{domain}") and d != domain and not d.startswith('*.'):
                    subdomains.add(d)
        
        # --- Format the output ---
        output = f"**🔎 Subdomain Enumeration for:** `{domain}`\n"
        
        if subdomains:
            sorted_subdomains = sorted(list(subdomains))
            count = len(sorted_subdomains)
            
            output += f"**✅ Found {count} Unique Subdomains:**\n"
            output += "```\n"
            output += "\n".join(sorted_subdomains[:20]) # Limit to 20 for brevity in Telegram
            if count > 20:
                output += f"\n...and {count - 20} more."
            output += "\n```"
        else:
            output += f"❌ **No unique subdomains found** in CT logs for `{domain}`."

        return output

    except requests.exceptions.Timeout:
        return "Error: Subdomain query timed out after 15 seconds."
    except requests.exceptions.RequestException as e:
        return f"Error during crt.sh API request: {e}"
    except Exception as e:
        # This catches JSON decode errors if the API returns non-JSON data
        return f"An unexpected error occurred during subdomain lookup: {e}"

# ... rest of your utility functions ...

# --- HANDLER FUNCTIONS ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Sends a greeting message when the user sends /start."""
    user = update.effective_user
    await update.message.reply_html(
        f"Hello, {user.mention_html()}! I am your ethical OSINT tool. Send /help to see commands.",
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Sends a message with the list of available commands."""
    help_text = (
        "**🤖 Ethical OSINT Analyzer Commands**\n"
        "This bot performs open-source intelligence lookups using public APIs and libraries.\n\n"
        "**Available Commands:**\n"
        "• `/start` - Greet the user and introduce the bot.\n"
        "• `/help` - Show this list of commands.\n"
        "• `/domain <domain>` - Fetches DNS records (A, MX, NS, TXT) for the specified domain.\n"
        "  *Example:* `/domain microsoft.com`\n"
        "• `/cve <CVE_ID>` - Searches the National Vulnerability Database (NVD) for details on a specific Common Vulnerability and Exposures (CVE) ID.\n"
        "  *Example:* `/cve CVE-2024-21413`\n\n"
        "• **`/geoip <target>`** - Looks up the geographical location, ISP, and organization associated with an IP address or domain.\n"  # <-- ADDED
        "  *Example:* `/geoip 1.1.1.1` or `/geoip google.com`\n\n"
        "• **`/subdomain <domain>`** - Fetches subdomains for a domain using public Certificate Transparency logs (crt.sh).\n" # <-- ADDED
        "  *Example:* `/subdomain tesla.com`\n\n"
        "*(Note: All results are based on publicly available data.)*"
    )
    await update.message.reply_text(help_text, parse_mode='Markdown')

async def post_init(application: ApplicationBuilder) -> None:
    """Sets the official list of commands for the Telegram client's command menu."""
    commands = [
        BotCommand("start", "Greet the user"),
        BotCommand("help", "Show all available commands"),
        BotCommand("domain", "<domain> - Fetches DNS records"),
        BotCommand("cve", "<CVE_ID> - Searches the NVD for vulnerability details"),
        BotCommand("geoip", "<target> - Looks up geographical location by IP/domain"),
        BotCommand("check", "<username> - Checks username presence across social media"),
        BotCommand("subdomain", "<domain> - Fetches subdomains from CT logs"),
        # You would add /whois here when you implement it!
    ]
    
    # Send the command list to the Telegram API
    await application.bot.set_my_commands(commands)
    print("Command list registered with Telegram.")

async def domain_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles the /domain command with arguments."""
    if not context.args:
        await update.message.reply_text("Usage: `/domain <domain_name>`\nExample: `/domain google.com`", parse_mode='Markdown')
        return

    domain_to_check = context.args[0].lower()
    await update.message.reply_text(f"🔍 **Analyzing DNS records for:** `{domain_to_check}`...\n", parse_mode='Markdown')
    result_text = perform_dns_lookup(domain_to_check)
    await update.message.reply_text(result_text, parse_mode='Markdown')

async def cve_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles the /cve command with arguments."""
    if not context.args:
        await update.message.reply_text("Usage: `/cve <CVE_ID>`\nExample: `/cve CVE-2024-21413`", parse_mode='Markdown')
        return

    cve_id = context.args[0].upper()
    await update.message.reply_text(f"🔍 **Searching NVD for:** `{cve_id}`...\n", parse_mode='Markdown')
    result_text = perform_cve_lookup(cve_id)
    await update.message.reply_text(result_text, parse_mode='Markdown')

# ... (start, help_command, domain_lookup, and cve_lookup handlers go here) ...

async def geoip_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles the /geoip command with an IP or domain argument."""
    
    # Check if a target argument was provided
    if not context.args:
        await update.message.reply_text(
            "Usage: `/geoip <IP_address_or_domain>`\nExample: `/geoip 8.8.8.8` or `/geoip cnn.com`", 
            parse_mode='Markdown'
        )
        return

    # Take the first argument provided
    target = context.args[0]
    
    await update.message.reply_text(f"🔍 **Looking up GeoIP data for:** `{target}`...", parse_mode='Markdown')

    # Run the GeoIP lookup
    result_text = perform_geoip_lookup(target)

    # Send the result
    await update.message.reply_text(result_text, parse_mode='Markdown')

# ... rest of your handler functions ...    

async def username_check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles the /check command with a username argument."""
    
    if not context.args:
        # This usage message uses Markdown as it contains no links
        await update.message.reply_text(
            "Usage: `/check <username>`\nExample: `/check elonmusk`", 
            parse_mode='Markdown'
        )
        return

    target_username = context.args[0]
    
    await update.message.reply_text(f"🔍 **Searching for profiles of:** `{target_username}`. This may take a minute...", parse_mode='Markdown')

    # Run the username check
    result_text = perform_username_check(target_username)

    # Send the result (using HTML parse mode for the links)
    await update.message.reply_text(result_text, parse_mode='HTML')

# ... (start, help_command, domain_lookup, cve_lookup, geoip_lookup, and username_check handlers go here) ...

async def subdomain_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles the /subdomain command with a domain argument."""
    
    # Check if a target argument was provided
    if not context.args:
        await update.message.reply_text(
            "Usage: `/subdomain <domain>`\nExample: `/subdomain tesla.com`", 
            parse_mode='Markdown'
        )
        return

    # Take the first argument provided
    target_domain = context.args[0]
    
    await update.message.reply_text(f"🔍 **Searching CT logs for subdomains of:** `{target_domain}`...", parse_mode='Markdown')

    # Run the subdomain lookup
    result_text = perform_subdomain_enum(target_domain)

    # Send the result
    await update.message.reply_text(result_text, parse_mode='Markdown')

# ... rest of your handler functions ...    

# --- MAIN BOT RUNNER (Consolidated) ---
def main():
    """Starts the bot."""
    print("Initializing bot...")
    
    # Create the application builder instance
    application = ApplicationBuilder().token(TOKEN).build()
    
    # Register ALL command handlers here
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command)) # Added missing help handler
    application.add_handler(CommandHandler("domain", domain_lookup))
    application.add_handler(CommandHandler("cve", cve_lookup))
    application.add_handler(CommandHandler("geoip", geoip_lookup))
    application.add_handler(CommandHandler("check", username_check))
    application.add_handler(CommandHandler("subdomain", subdomain_lookup))
    
    # Start polling (listening for messages)
    print("Bot is running and listening...")
    application.run_polling(poll_interval=1)

if __name__ == '__main__':
    main()