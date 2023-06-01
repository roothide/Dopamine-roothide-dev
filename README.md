<img src="https://github.com/opa334/Dopamine/assets/52459150/ed04dd3e-d879-456d-9aa3-d4ed44819c7e" width="64" />

# Dopamine(RootHide)

RootHide aims to provide a completely hidden jailbreak solution without inject/modify/patch/hook apps.

This project is the dopamine implementation of RootHide Jailbreak.

# Progress

- [x]  Remove fakelib
- [x]  Remove bind mount
- [x]  Remove system-wide dyld file patch
- [x]  Unsandbox systemhook.dylib before injected it
- [x]  Randomize systemhook.dylib file name
- [ ]  Randomize /var/jb/ fixed path
- [ ]  linker/loader works with randomized /var/jb/
- [ ]  Implements a middle layer to convert path
- [ ]  Implement a libc shim to auto convert path
- [ ]  Implement a libc++ shim to auto convert path
- [ ]  Implement a libobjc shim to auto convert path
- [ ]  Implement a libswift shim to auto convert path
- [ ]  Auto redirect to shim library when compile/link
- [ ]  Adapt theos for RootHide
- [ ]  Adapt bootstrap for RootHide
- [ ]  Adapt Sileo store for RootHide
- [ ]  Adapt Zebra store for RootHide
- [ ]  Adapt Filza file manager for RootHide
- [ ]  Adapt NewTerm app for RootHide

# Credits

[@opa334](https://github.com/opa334/)

[@procursus](https://github.com/ProcursusTeam/Procursus)

[@theos](https://github.com/theos/theos)
