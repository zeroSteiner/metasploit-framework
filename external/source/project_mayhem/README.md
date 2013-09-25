# Project Mayhem
## About
### License
Project Mayhem is released under the BSD license, with the exception of the cJSON component which is provided under it's original MIT license.
### Project Mayhem Support
Currently only 32-bit Dynamics processes can be infected.  The code was tested extensively against version 10.00.1841

### Credits
+ Spencer McIntyre @zeroSteiner (SecureState R&I)
+ Tom Eston @agent0x0 (SecureState Profiling)

## Compiling

1. Use Visual Studio on Windows, start a new project from File > Project From Existing Code
1. Set the type of project to "Visual C++"
1. Set the Project file location to the external/source/project_mayhem folder
1. Under "How do you want to build the project?" select "Use Visual Studio" and set Project type to "Dynamically linked library (DLL) project"
1. After the project has been created set the configuration to Release and build it.

The cJSON library will cause a few warnings to be thrown when Project Mayhem is compiled.

## Usage

1. Run post/windows/manage/dynamics/install while Dynamics is running
1. Wait for Dynamics to be used for a valid handle to be copied
1. Use one of the other post/windows/manage/dynamics modules
