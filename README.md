# ChatGPT-utils: Controlled Windows BugCheck (Blue Screen of Death)

This Visual Studio solution contains **two projects**:

* A Kernel Driver project.
* A Windows Application project that communicates with the driver.

> ⚠️ **Warning:** This tool triggers a real Blue Screen of Death (BSOD). Use only in a **virtual machine** for testing. Running on a host system will crash it immediately.

---

## Directions for Use

On first launch of the application, run with `--make-service` to set up the driver service.  

The driver's `.sys` file must be in the same folder as the executable.

### Syntax

ControlledBSOD.exe [switches] [BugCheck Code] [p1 p2 p3 p4]


### Switches

* `--make-service` – Creates a service so the application can communicate with the driver.
* `--verbose` – Enables detailed logging.
* `--help` – Shows the help message.
* `--no-vm-check` – Skips the hypervisor/VM detection check.
* `--enable-testsigning` - Enables Test Signing and Attempts to Restart.
### Examples

ControlledBSOD.exe --make-service --verbose 0x000000D1

ControlledBSOD.exe --verbose 0x000000D2

ControlledBSOD.exe --make-service 0x0000001E --verbose


---

## Requirements

* Windows 10 or higher.
* Test Signing mode enabled in BCD (required for unsigned drivers).
* Administrator privileges.
* A virtual machine for safe testing (strongly recommended).

---

## Build Requirements

* Windows Driver Kit (WDK) version 1.33
* Visual Studio 2022 with Desktop Development with C++ workload
* Windows 11 SDK

---

## How It Works

The Windows BugCheck can be triggered via the `KeBugCheckEx` function. This allows specifying a BugCheck code and up to four parameters.  

Once called, the system immediately terminates all running processes and crashes, so the function does not return.  

A `return` statement is included in the code purely to satisfy compiler requirements.

---

## Safety Notes

* **Always test in a virtual machine.**  
* Do not run on a production or host machine.  
* Enabling Test Signing mode is required if unsigned drivers are used. The application can prompt and enable it automatically.
