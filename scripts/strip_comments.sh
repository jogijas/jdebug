#!/bin/bash

# ==============================================================================
# Script Name: strip_comments.sh
# Description: Safely removes both single-line (//) and multi-line (/* */)
#              comments from C/C++ source files. Uses an advanced regular
#              expression engine to ensure comments embedded within string
#              literals (e.g., printf("http://urls")) are left completely intact.
# ==============================================================================

# Exit immediately if a command exits with a non-zero status
set -e

# Print usage instructions
print_usage() {
    echo "Usage: $0 [OPTIONS] <input_file.c>"
    echo ""
    echo "Options:"
    echo "  -i, --inplace    Modify the input file in-place (overwrites original)"
    echo "  -o, --output     Specify an explicit output file path"
    echo "  -h, --help       Display this help menu"
    echo ""
    echo "Example:"
    echo "  $0 source.c > clean.c"
    echo "  $0 -i source.c"
}

# Initialize variables
INPLACE=false
OUTPUT_FILE=""
INPUT_FILE=""

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            print_usage
            exit 0
            ;;
        -i|--inplace)
            INPLACE=true
            shift
            ;;
        -o|--output)
            if [[ -z "$2" || "$2" == -* ]]; then
                echo "Error: --output requires a valid file path argument." >&2
                exit 1
            fi
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -*)
            echo "Error: Unknown option '$1'" >&2
            print_usage
            exit 1
            ;;
        *)
            if [[ -n "$INPUT_FILE" ]]; then
                echo "Error: Multiple input files specified specified ('$INPUT_FILE' and '$1')." >&2
                print_usage
                exit 1
            fi
            INPUT_FILE="$1"
            shift
            ;;
    esac
done

# Validate input file requirements
if [[ -z "$INPUT_FILE" ]]; then
    echo "Error: No input file specified." >&2
    print_usage
    exit 1
fi

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Error: Input file '$INPUT_FILE' does not exist or is not a regular file." >&2
    exit 1
fi

# Ensure conflicting combinations are caught
if [ "$INPLACE" = true ] && [ -n "$OUTPUT_FILE" ]; then
    echo "Error: Cannot combine --inplace (-i) and --output (-o) options." >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# Core Comment Strip Processing Logic
# ------------------------------------------------------------------------------
# We utilize a Perl interpretation pipeline with a non-destructive capture trick:
# Pattern: ('[^']*'|"[^"]*")|/\*.*?\*/|//.*?(?=\n)
# Explanation:
#   1. ('[^']*'|"[^"]*") maps and captures valid text strings or single characters.
#   2. If a string is matched, it falls into Capture Group 1 ($1) and is written back.
#   3. If a comment block (/* ... */ or // ...) matches, Group 1 is empty, so the
#      comment is completely stripped out without altering strings containing URLs or tokens.
# ------------------------------------------------------------------------------
strip_comments() {
    perl -0777 -pe '
        s/
            ( "[^"\\]*(?:\\.[^"\\]*)*" | '\''[^'\''\\]*(?:\\.[^'\''\\]*)*'\'' ) # Match and capture strings
            | \/\*[\s\S]*?\*\/                                                  # Match multi-line blocks
            | \/\/.*                                                            # Match single-line comments
        /$1/gx
    ' "$1"
}

# Execute processing based on destination options
if [ "$INPLACE" = true ]; then
    # In-place tracking using a safe localized atomic swap
    TEMP_FILE=$(mktemp)
    strip_comments "$INPUT_FILE" > "$TEMP_FILE"
    mv "$TEMP_FILE" "$INPUT_FILE"
    echo "[*] Comments cleanly stripped in-place from file: $INPUT_FILE"
elif [[ -n "$OUTPUT_FILE" ]]; then
    # Route output directly to target designated location
    strip_comments "$INPUT_FILE" > "$OUTPUT_FILE"
    echo "[*] Clean output successfully saved to location: $OUTPUT_FILE"
else
    # Default behavior prints out onto stdout pipelines
    strip_comments "$INPUT_FILE"
fi
