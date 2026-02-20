import os
import subprocess
from typing import Optional
from fastmcp import FastMCP

# Create the MCP server
mcp = FastMCP("amass")


@mcp.tool()
def amass(
    subcommand: str,
    domain: Optional[str] = None,
    intel_whois: Optional[bool] = None,
    intel_organization: Optional[str] = None,
    enum_type: Optional[str] = None,
    enum_brute: Optional[bool] = None,
    enum_brute_wordlist: Optional[str] = None
) -> str:
    """
    Advanced subdomain enumeration and reconnaissance tool.
    
    Args:
        subcommand: Specify the Amass operation mode - "enum" for subdomain enumeration 
                    and network mapping, or "intel" for gathering intelligence about 
                    target domains from various sources.
        domain: Target domain to perform reconnaissance against (e.g., example.com)
        intel_whois: Whether to include WHOIS data in intelligence gathering (true/false)
        intel_organization: Organization name to search for during intelligence gathering 
                            (e.g., 'Example Corp')
        enum_type: Enumeration approach type - "active" includes DNS resolution and 
                   potential network interactions, "passive" only uses third-party sources
        enum_brute: Whether to perform brute force subdomain discovery (true/false)
        enum_brute_wordlist: Path to custom wordlist file for brute force operations
    """
    if subcommand not in ["enum", "intel"]:
        return f"Error: subcommand must be 'enum' or 'intel', got '{subcommand}'"
    
    amass_args = ["amass", subcommand]
    
    # Handle enum subcommand
    if subcommand == "enum":
        if not domain:
            return "Error: Domain parameter is required for 'enum' subcommand"
        
        amass_args.extend(["-d", domain])
        
        # Handle enum type
        if enum_type == "passive":
            amass_args.append("-passive")
        # active is the default
        
        # Handle brute force options
        if enum_brute:
            amass_args.append("-brute")
            if enum_brute_wordlist:
                amass_args.extend(["-w", enum_brute_wordlist])
    
    # Handle intel subcommand
    elif subcommand == "intel":
        if not domain and not intel_organization:
            return "Error: Either domain or organization parameter is required for 'intel' subcommand"
        
        # Add domain if provided
        if domain:
            if not intel_whois:
                return "Error: For domain parameter, whois is required"
            amass_args.extend(["-d", domain])
        
        # Add organization if provided
        if intel_organization:
            amass_args.extend(["-org", intel_organization])
        
        # Add whois flag if enabled
        if intel_whois:
            amass_args.append("-whois")
    
    # Execute amass command
    print(f"Executing: {' '.join(amass_args)}")
    
    try:
        result = subprocess.run(
            amass_args,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        output = result.stdout
        if result.stderr:
            output += f"\nStderr: {result.stderr}"
        
        if result.returncode != 0:
            return f"Amass exited with code {result.returncode}. Output: {output}"
        
        return output if output else "Amass completed successfully with no output"
        
    except subprocess.TimeoutExpired:
        return "Error: Amass command timed out after 5 minutes"
    except FileNotFoundError:
        return "Error: Amass binary not found. Please ensure amass is installed."
    except Exception as e:
        return f"Error executing amass: {str(e)}"


# Run the server
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    
    # Use streamable-http transport for FastMCP 3.0
    # This creates the /mcp endpoint that accepts POST requests
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port,
        path="/mcp"
    )
