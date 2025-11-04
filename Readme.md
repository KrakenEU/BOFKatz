# BOFKatz

A Beacon Object File (BOF) implementation of Mimikatz that executes in memory with advanced evasion techniques. BOFKatz uses Process Hollowing and command-line argument spoofing to avoid detection by security products.

## Features

- **In-Memory Execution**: Runs Mimikatz entirely in memory without touching disk
- **Argument Spoofing**: Masks command-line arguments to evade EDR detection
- **Process Hollowing**: Uses legitimate processes to host the payload
- **Flexible Arguments**: Supports multiple Mimikatz commands and arguments with spaces
- **Stealth Mode**: Default "coffee" mode for discreet operation

## Usage

### Default Behavior

```
BOFKatz
```

Executes with default `coffee` command and automatically exits.

### Basic Mimikatz Commands

```
BOFKatz "privilege::debug" "sekurlsa::logonpasswords"
```

Runs privilege escalation and dumps logon passwords.

### Commands with Spaces

```
BOFKatz coffee "lsadump::trust /patch"
```

Executes LSA dump trust command with patch argument (note the quotes for arguments containing spaces).

### Example Usage

```
BOFKatz token::elevate privilege::debug sekurlsa::logonpasswords
```

## Evasion Techniques

### Command-Line Spoofing
BOFKatz uses advanced Process Hollowing techniques to:
- Create processes with benign-looking command lines
- Modify the PEB in memory to inject real commands
- Appear as legitimate system processes in monitoring tools

### Memory Operations
- No disk writes - entire execution happens in memory
- Uses reflective loading techniques
- Cleans up after execution automatically

## Building

### Requirements
- Visual Studio Build Tools
- MinGW or similar C compiler
- Beacon Object File compatible C2 framework

### Compilation

```
make
```

## Integration

BOFKatz is has been only tested with HavocC2 for the moment


## Credits

**Created by KrakenEU**

-  LinkedIn: [Iaki Tornos](https://www.linkedin.com/in/i%C3%B1aki-tornos-572580177/)
-  YouTube: [@Kr4k3nEU](https://www.youtube.com/@Kr4k3nEU)

## Legal Disclaimer

This tool is intended for:
- Authorized penetration testing
- Security research
- Educational purposes

Always ensure you have proper authorization before using this tool. The creators are not responsible for misuse or damage caused by this software.

## License

This project is for educational and authorized security testing purposes only.
