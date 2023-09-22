# MaldevAcademyLdr.1

## EXE Loader

<a target="_blank" href="https://maldevacademy.com/">Maldev Academy</a>'s October update saw several interesting modules being released to our users. One of them was our DLL loader that was successfully tested against several EDRs including MDE and Crowdstrike.

We promised to release an EXE version of the loader on GitHub.

| ![tweet](https://github.com/Maldev-Academy/MaldevAcademyLdr.1/assets/28691727/ecda3186-cc33-452d-8ec5-f4f8e0a2c938) |
|:--:| 
| *https://twitter.com/MalDevAcademy/status/1701981413938012462* |

## Features

* Indirect-Syscalls using an improved HellsHall implementation.

* Dll Unhooking via the \KnownDlls\ directory

* Payload injection by chunking

* Using custom AES encryption library.

* Executing payload via Thread Pool APIs.

* Obfuscating IAT using API hashing and API camouflage.

* CRT library independent.

## Demo


