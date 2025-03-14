#!/bin/bash

# Function for fancy print
fancy_echo() {
    echo -e "\033[1;34m$1\033[0m" # Blue text
}

# Check for AVX support in /proc/cpuinfo
AVX_SUPPORT=$(grep -o -m 1 'avx' /proc/cpuinfo)

# Header
fancy_echo "***********************************************"
fancy_echo "           CPU AVX Support Check              "
fancy_echo "***********************************************"

# Display CPU Model Information
fancy_echo "\n📄 CPU Model Information:"
lscpu | grep 'Model name'

# Check if AVX is supported and display appropriate message
if [ -z "$AVX_SUPPORT" ]; then
    fancy_echo "\n🚫 AVX is NOT supported by your CPU. 🚫"

    # Suggestion message if AVX is not supported
    fancy_echo "\n💡 Suggestion:"
    fancy_echo "If AVX is required by your software and is not supported, consider upgrading to a CPU that supports AVX."
else
    fancy_echo "\n✅ AVX is supported by your CPU. ✅"
fi

fancy_echo "***********************************************"
fancy_echo "       End of CPU AVX Support Check           "
fancy_echo "***********************************************"
