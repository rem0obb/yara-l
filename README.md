# YARA-L

Yara-L is a project that binds Yara to the Lua Lang.

# For development

To perform a build, you will need to have the Yara library installed on your machine and Lua 5.4. To perform the build, simply follow these steps.

### Clone the Repository
```
git clone --recurse-submodules -j8 git@github.com:exoctl/exoctl.git
``` 

### Build on Linux

```sh
mkdir -p build
cd build
cmake ..
make -j8
```

# Examples usage

```
require("yaral")  

local yara = Yara.new()

yara:set_rule_buff('rule Test { condition: true }', 'Namespace_Test')
yara:load_rules()

yara:scan_bytes("buffer", function(message, data)
    if message == YaraFlags.RuleMatching then
        print("Matched: " .. data.identifier)
    end
end, YaraFlags.FastMode)
```
# Docs

To view the documentation and examples, simply access [DOCS](DOCS.md).