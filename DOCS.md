# Yara-L Docs

Yara Lua Extension is a C++ binding that integrates the YARA library with Lua using Sol3. It provides Lua interfaces to YARA's core structures and functions, enabling rule compilation, loading, scanning, and manipulation directly from Lua scripts.

> [!NOTE]  
> This bind was decoupled from my engine, exoctl. If you want to see real examples, you can view the Lua code here: [exoctl/plugins/yara_gate](https://github.com/exoctl/exoctl/tree/main/sources/app/plugins/yara_gate)

> [!WARNING]  
> There is currently no support for Windows; I need to take some time to compile it for that version.

## Features

- Bindings for key YARA structures like rules, metas, strings, namespaces, and modules.
- Support for loading and saving rules from files, buffers, or custom streams.
- Callback mechanisms for scan events, such as rule matching and module imports.
- Enumeration of flags for scan modes, callback messages, and return codes.
- Integration with Lua's userdata and enums for seamless interaction.
- Exception handling for runtime errors in callbacks.
- Thread Safe

## Installation

To use this extension, you need to build it from source. It depends on:

- YARA library (libyara)
- Lua 5.4+
- Sol3 (Lua binding library)
- fmt library for formatting

### Building

1. Clone the repository (assuming it includes submodules for dependencies like Sol3):

```
git clone --recurse-submodules -j8 <repository-url>
```

2. Create a build directory:

```
mkdir build
cd build
```

3. Configure with CMake:

```
cmake ..
```

4. Build:

```
make -j8
```

This will produce a shared library (e.g., yaral.so) that can be loaded in Lua via `require`.

## Usage

Load the module in Lua:

```lua
local yara = require("yaral") 
```

### Creating a Yara Instance

```lua
local y = Yara:new()
```

### Binding Structures

The extension binds several YARA structures as Lua usertypes:

#### Import

Represents a module import.

- Fields:
  - `module_name`: string (readonly) - Name of the imported module.

Example:

```lua
local import = Import:new()
print(import.module_name)
```

#### String

Represents a string in a YARA rule.

- Fields:
  - `flags`: integer (readonly) - String flags.
  - `idx`: integer (readonly) - Index.
  - `fixed_offset`: integer (readonly) - Fixed offset.
  - `rule_idx`: integer (readonly) - Rule index.
  - `length`: integer (readonly) - Length of the string.
  - `string`: string (property) - The string content.
  - `identifier`: string (readonly) - Identifier.

Example:

```lua
local str = String:new()
print(str.identifier, str.length, str.string)
```

#### Namespace

Represents a YARA namespace.

- Fields:
  - `name`: string (readonly) - Namespace name.
  - `idx`: integer (readonly) - Index.

Example:

```lua
local ns = Namespace:new()
print(ns.name)
```

#### Meta

Represents metadata in a YARA rule.

- Fields:
  - `flags`: integer (readonly) - Flags.
  - `type`: integer (readonly) - Type (e.g., integer or string).
  - `identifier`: string (readonly) - Identifier.
  - `integer`: integer (readonly) - Integer value (if applicable).
  - `string`: string (readonly) - String value (if applicable).

Example:

```lua
local meta = Meta:new()
print(meta.identifier, meta.type, meta.string or meta.integer)
```

#### Rule

Represents a YARA rule.

- Fields:
  - `flags`: integer (readonly) - Rule flags.
  - `num_atoms`: integer (readonly) - Number of atoms.
  - `required_strings`: integer (readonly) - Required strings.
  - `identifier`: string (readonly) - Rule identifier.
  - `tags`: table (readonly) - Tags.
  - `ns`: Namespace (readonly) - Namespace.
  - `strings`: table (readonly) - Strings.
  - `metas`: table (readonly) - Metas.

Example:

```lua
local rule = Rule:new()
print(rule.identifier, rule.flags)
```

#### Stream

Represents a YARA stream for custom I/O.

- Methods:
  - `read(func)`: Sets a Lua function for reading from the stream.
    - The function takes `total_size` and returns a string.
  - `write(func)`: Sets a Lua function for writing to the stream.
    - The function takes a string and returns the count.

Example:

```lua
local stream = Stream:new()
stream:read(function(total_size)
    -- Return data as string
    return "some data"
end)
stream:write(function(data)
    -- Handle data
    print(data)
    return #data
end)
```

#### Flags

Enum for YARA flags, including callback messages, return codes, and scan flags.

- Values:
  - Callback messages: `RuleMatching`, `RuleNotMatching`, `ScanFinished`, `ImportModule`, `ModuleImported`, `TooManyMatches`, `ConsoleLog`, `TooSlowScanning`.
  - Callback returns: `ContinueScan`, `AbortScan`, `ErrorScan`.
  - Scan flags: `FastMode`, `ProcessMemory`, `NoTryCatch`, `ReportRulesMatching`, `ReportRulesNotMatching`.

Example:

```lua
print(YaraFlags.FastMode)
```

### Yara Methods

The main `Yara` usertype provides core functionality:

- `rule_disable(rule_identifier: string)`: Disables a rule.
- `rule_enable(rule_identifier: string)`: Enables a rule.
- `unload_rules()`: Unloads loaded rules.
- `load_rules_stream(stream: Stream)`: Loads rules from a stream.
- `rules_foreach(func)`: Iterates over rules with a callback.
- `metas_foreach(rule: Rule, func)`: Iterates over metas.
- `tags_foreach(rule: Rule, func)`: Iterates over tags.
- `strings_foreach(rule: Rule, func)`: Iterates over strings.
- `save_rules_stream(stream: Stream)`: Saves rules to a stream.
- `load_compiler()`: Loads the compiler.
- `unload_compiler()`: Unloads the compiler.
- `set_rules_folder(path: string)`: Sets the rules folder.
- `load_rules()`: Loads rules from set sources.
- `scan_bytes(buffer: string, func: function, flags: Flags)`: Scans a buffer with a callback.
  - Callback receives `message` and optional `data` (e.g., Rule or String).
- `load_rules_file(path: string)`: Loads from a file.
- `set_rule_buff(buffer: string, namespace: string)`: Sets rule from buffer.
- `set_rule_file(path: string, namespace: string)`: Sets rule from file.
- `save_rules_file(path: string)`: Saves to a file.

#### Scan Callback Details

The scan callback function handles different messages:

- `RuleMatching` or `RuleNotMatching`: Receives `YR_RULE`.
- `ScanFinished`: Receives `nil`.
- `TooManyMatches`: Receives `YR_STRING`.
- `ConsoleLog`: Receives log string.
- `ImportModule`: Receives `YR_MODULE_IMPORT`.
- Others: Receives message only.

Return `ContinueScan`, `AbortScan`, or `ErrorScan` from the callback.

Example Scan:

```lua
y:scan_bytes("scan this text", function(message, data)
    if message == YaraFlags.RuleMatching then
        print("Matched rule: " .. data.identifier)
    elseif message == YaraFlags.ScanFinished then
        print("Scan complete")
    end
    return YaraFlags.ContinueScan
end, YaraFlags.FastMode)
```

## Error Handling

Callbacks throw `lua::exception::Runtime` on errors, using fmt for messages.

## Full Example

```lua
require("yaral")

local y = Yara:new()

-- Set a rule
y:set_rule_buff('rule Test { condition: true }', 'TestNamespace')

-- Load rules
y:load_rules()

-- Scan
y:scan_bytes("any buffer", function(message, data)
    if message == YaraFlags.RuleMatching then
        print("Matched: " .. data.identifier)
    end
    return YaraFlags.ContinueScan
end, YaraFlags.FastMode)
```