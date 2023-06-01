# Dopamine(RootHide)

RootHide aims to provide a completely hidden jailbreak solution without inject/modify/patch/hook apps.

This project is the RootHide Jailbreak implementation based on Dopamine.


# Progress

- [x]  Remove fakelib
- [x]  Remove bind mount
- [x]  Remove system-wide dyld file patch
- [x]  Unsandbox systemhook.dylib before injected it
- [x]  Randomize systemhook.dylib file name
- [ ]  Randomize the /var/jb/ fixed path
- [ ]  Add jailbreak environment variable
- [ ]  linker/loader works with randomized /var/jb/
- [ ]  Implements a middle layer to convert path
- [ ]  Implement a libc shim to auto convert path
- [ ]  Implement a libc++ shim to auto convert path
- [ ]  Implement a libobjc shim to auto convert path
- [ ]  Implement a libswift shim to auto convert path
- [ ]  Auto redirect to shim library when compile/link
- [ ]  A tool to auto redirect to shim for mach-o
- [ ]  Adapt theos tools for RootHide
- [ ]  Adapt bootstraps for RootHide
- [ ]  Adapt Sileo store for RootHide
- [ ]  Adapt Zebra store for RootHide
- [ ]  Adapt NewTerm app for RootHide
- [ ]  Adapt Filza manager for RootHide
- [ ]  Implement a blacklist selector app


# Credits

[@opa334](https://github.com/opa334/)

[@procursus](https://github.com/ProcursusTeam/Procursus)

[@theos](https://github.com/theos/theos)


# Info

[procursus_discord_server](https://discord.gg/QJDrrAJPDY)

[theos_discord_server](https://theos.dev/discord)

