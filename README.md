# A Controlled Windows BugCheck (Blue screen of death).

This Visual studio solution contains Two Projects;

* One for a Kernel Driver.

* One for a Windows Application that Talks to the Driver.

# Directions of Use

On first Launch of App, use --make-service to set up the Service.

The Driver's .sys file must be in the Same folder as the exe.
#### Syntax

ControlledBSOD.exe [switches] [BugCheck Code] [p1 p2 p3 p4]

#### Switches
--make-service: Makes a Service for the Application to be able to Contact the driver

--verbose: enables verbose Logging

--help: shows a help message

--skip-vm-check: skips the HyperVisor\VM check.

#### Examples

ControlledBSOD.exe --make-service --verbose 0x000000D1

ControlledBSOD.exe --verbose 0x000000D2

# Requirements

* A Machine Running Windows 10 or higher. (Required)

* Test Signing Enabled in BCD. (Required)

* A Virtual Machine for Safe testing. (Optional)

* Administrator Privileges. (Required)

# Build Requirements

* Windows Driver Kit Version 1.33

* Visual Studio 2022 w/Desktop Development with C++ Workload 

* Windows 11 SDK
