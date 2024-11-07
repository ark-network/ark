#!/bin/bash

# Create an empty array to store signing times
signing_times=()

# Loop over each log file in the ./log directory
for file in ./client_client_*.log; do
    # Check if the file exists
    if [[ -f "$file" ]]; then
        # Extract the signing time from lines that match the pattern and append to array
        while IFS= read -r line; do
            # Use sed to extract the signing time
            time_taken=$(echo "$line" | sed -n 's/.*signing took \([0-9.]*\)s/\1/p')
            if [[ $time_taken ]]; then
                signing_times+=("$time_taken")
            fi
        done < "$file"
    fi
done

# Sort the array in ascending order and print
IFS=$'\n' sorted_times=($(sort -n <<<"${signing_times[*]}"))
unset IFS

# Display only the seconds values, no additional text
for time in "${sorted_times[@]}"; do
    echo "$time"
done
