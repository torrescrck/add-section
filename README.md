# add-section
PE file manipulation tool that adds a new section to a windows executable, commonly used for code injection, packer research, and reverse engineering experiments
🧩 AddSection – PE Section Injection Tool
add section is a low-level Portable Executable (PE) manipulation utility for windows that demonstrates how to safely add a new section to an existing executable.

This technique is commonly used in:

Code injection research
Packer & protector experimentation
Malware analysis (red-team/blue team learning)
Reverse Engineering & PE format education

What this tool does
Parses Pe headers (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS)
Calculates proper section alignment
Add a new executable sction to the binary
Updates
Number of sections
SizeofImage
Section headers correctly

Preserves validity so the file still loads

This project is intended for educational and research purposes only, helping security researchers understand:
How PE files are structures internally
How Basic injection methods often fail against modern protections
The foundations behind packers, loaders, and injectors

🚫 Important Notes
This is a classic technique and not stealthy against modern anti-cheat/EDR systems
Modern protection often detect:
NEW PE secions
Modified headers
Section permission

For advanced techniques prefer:
Slack space injection
Entry-point grafting
Post-unpack runtime execution

🛠️ Typical Use Cases
Learning PE internals
Building custom packers/loaders
Reverse enginering practive
comparing classic vs modern techniques

📚 Related Topics
Packer/protector
Code Injection
Reverse engineering
Pe file format

👤 Author
Alejandro Torres (torrescrack)
HackingMexico / Guided Hacking contributor
