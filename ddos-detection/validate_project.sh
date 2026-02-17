#!/bin/bash

echo "Validating DDoS Detection Project..."
ERRORS=0

echo -n "Checking Python version... "
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python $PYTHON_VERSION"

echo -n "Checking virtual environment... "
if [ -d "venv" ]; then
    echo "✓ Found"
else
    echo "✗ Not found"
    ((ERRORS++))
fi

echo "Checking directories..."
for dir in src tests notebooks docs data models; do
    echo -n "  $dir... "
    if [ -d "$dir" ]; then
        echo "✓"
    else
        echo "✗ Missing"
        ((ERRORS++))
    fi
done

if [ $ERRORS -eq 0 ]; then
    echo "✓ Project validation passed!"
else
    echo "✗ Found $ERRORS error(s)"
fi
