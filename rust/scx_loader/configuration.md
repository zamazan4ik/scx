# scx_loader Configuration File

The `scx_loader` can be configured using a TOML file. This file allows you to customize the default scheduler mode, specify custom flags for each supported scheduler and mode, and set a default scheduler to start on boot.

## Configuration File Location

`scx_loader` looks for the configuration file in the following paths (in order):

1. `/etc/scx_loader/config.toml`
2. `/etc/scx_loader.toml`

If no configuration file is found at any of these paths, `scx_loader` will use the built-in default configuration.

## Configuration Structure

The configuration file has the following structure:

```toml
default_sched = "scx_bpfland"
default_mode = "Auto"

[scheds.scx_bpfland]
auto_mode = []
gaming_mode = ["-k", "-m", "performance"]
lowlatency_mode = ["--lowlatency"]
powersave_mode = ["-m", "powersave"]

[scheds.scx_rusty]
auto_mode = []
gaming_mode = []
lowlatency_mode = []
powersave_mode = []

[scheds.scx_lavd]
auto_mode = []
gaming_mode = ["--performance"]
lowlatency_mode = ["--performance"]
powersave_mode = ["--powersave"]
```

**`default_sched`:**

* This field specifies the scheduler that will be started automatically when `scx_loader` starts (e.g., on boot).
* It should be set to the name of a supported scheduler (e.g., `"scx_bpfland"`, `"scx_rusty"`, `"scx_lavd"`).
* If this field is not present or is set to an empty string, no scheduler will be started automatically.

**`default_mode`:**

* This field specifies the default scheduler mode that will be used when starting a scheduler without explicitly specifying a mode.
* Possible values are: `"Auto"`, `"Gaming"`, `"LowLatency"`, `"PowerSave"`.
* If this field is not present, it defaults to `"Auto"`.

**`[scheds.scx_name]`:**

* This section defines the custom flags for a specific scheduler. Replace `scx_name` with the actual name of the scheduler (e.g., `scx_bpfland`, `scx_rusty`, `scx_lavd`).

**`auto_mode`, `gaming_mode`, `lowlatency_mode`, `powersave_mode`:**

* These fields specify the flags to be used for each scheduler mode.
* Each field is an array of strings, where each string represents a flag.
* If a field is not present or is an empty array, the default flags for that mode will be used.

## Example Configuration

The example configuration above shows how to set custom flags for different schedulers and modes, and how to configure `scx_bpfland` to start automatically on boot.

* For `scx_bpfland`:
    * Gaming mode: `-k -m performance`
    * Low Latency mode: `--lowlatency`
    * Power Save mode: `-m powersave`
* For `scx_rusty`:
    * No custom flags are defined, so the default flags for each mode will be used.
* For `scx_lavd`:
    * Gaming mode: `--performance`
    * Low Latency mode: `--performance`
    * Power Save mode: `--powersave`

## Fallback Behavior

If a specific flag is not defined in the configuration file, `scx_loader` will fall back to the default flags defined in the code.

## Missing Required Fields

If the `default_mode` field is missing, it will default to `"Auto"`. If a `[scheds.scx_name]` section is missing, or if specific mode flags are missing within that section, the default flags for the corresponding scheduler and mode will be used. If `default_sched` is missing or empty, no scheduler will be started automatically.